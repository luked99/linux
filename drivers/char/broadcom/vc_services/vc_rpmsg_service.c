/*
 * Copyright (C) 2013 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/cdev.h>
#include <linux/circ_buf.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rpmsg.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/broadcom/vc_rpmsg_service.h>
#include <linux/broadcom/vc_suspend.h>

/*
 * Each VC service is exported as a char device. Opening the char device
 * creates a new rpmsg channel and some client state in this driver.
 * write() sends a message over the channel. Writing an OPEN message
 * sets up some client state on VC. All the state will be automatically
 * released when the device is closed.
 *
 * When certain control messages are received over the channel, they are
 * processed immediately. Other messages are stored in a small FIFO, and
 * read() returns the next message from that FIFO.
 *
 * Each client in this driver has a small state machine to track opening and
 * releasing, and to handle error conditions. It needs to reflect the state
 * held on VC, to guarantee we will always clean up properly when a client
 * is killed.
 *
 * Expected state transitions:
 *
 *   STARTED   -> [send MSG_OPEN]
 *             -> OPENING
 *
 *   STARTED   -> [send/recv any other message, or some error condition]
 *             -> RELEASED
 *
 *   OPENING   -> [recv MSG_OPEN_REPLY]
 *             -> [copy to client]
 *             -> OPEN
 *
 *   OPENING   -> [recv any other message, or some error condition]
 *             -> [abort_client]
 *             -> [send MSG_RELEASE]
 *             -> RELEASING
 *
 *   OPEN      -> [some error condition]
 *             -> [abort_client]
 *             -> [send MSG_RELEASE]
 *             -> RELEASING
 *
 *   OPEN      -> [recv MSG_UNMAP_BUFFERS]
 *             -> [unmap]
 *             -> [copy to client]
 *             -> OPEN
 *
 *   OPEN      -> [recv any other message]
 *             -> [copy to client]
 *             -> OPEN
 *
 *   RELEASING -> [recv MSG_RELEASE_REPLY]
 *             -> [copy to client]
 *             -> RELEASED
 *
 *   RELEASING -> [recv MSG_UNMAP_BUFFERS]
 *             -> [unmap]
 *             -> [copy to client]
 *             -> RELEASING
 *
 *   RELEASING -> [recv MSG_FATAL_ERROR UNKNOWN_CLIENT]
 *             -> RELEASED
 *
 *   RELEASING -> [some other error condition]
 *             -> RELEASING
 *
 *   RELEASED  -> [anything]
 *             -> RELEASED
 *
 * "some error condition" includes invalid messages from client/service,
 * client closing the char device, overflow of the client fifo, etc.
 *
 * MSG_RELEASE is only triggered once, and the client will receive no
 * messages after that. (The client might fail to receive some messages
 * from *before* the MSG_RELEASE too, since service_read() will fail
 * when called after the state transition, even if the client FIFO still
 * contains some messages. If a service protocol wants a pipeline of
 * multiple messages/replies in flight at once, it should flush its
 * pipeline before closing the connection.)
 *
 * Each client also maintains a list of ion buffers that have been mapped
 * into VC. (TODO: currently ion isn't supported, these are just vcsm
 * handles instead; they should be changed to ion.)
 */

struct buffer_idr_val {
	struct ion_handle *handle;
	int fd;
};

struct service_dev {
	struct rpmsg_channel *rpdev;
	dev_t devnum;
	struct cdev cdev;
	struct class *class;
};

enum client_state {
	CLIENT_STARTED,
	CLIENT_OPENING,
	CLIENT_OPEN,
	CLIENT_RELEASING,
	CLIENT_RELEASED,
};

/*
 * The client fifo is allocated with kmalloc, so this shouldn't be too
 * large (else allocation may fail when memory is fragmented) but should
 * be large enough that it won't overflow if the client has a slight
 * hiccup and stops reading for a bit
 */
#define CLIENT_FIFO_SIZE 4096

struct client {
	struct mutex mutex;
	struct service_dev *dev;
	struct rpmsg_endpoint *ept;

	enum client_state state;
	struct kfifo_rec_ptr_2 fifo;

	/* Wait queue for fifo and state */
	wait_queue_head_t readq;

	/* Active buffer mappings */
	struct idr buffer_idr;
	spinlock_t buffer_idr_lock;
};

static int translate_buffers_to_vc(struct client *client, int num_buffers,
				   char *msg, size_t len)
{
	struct device *dev = &client->dev->rpdev->dev;
	struct VC_SERVICE_BUFFER_USER_T buffer_user;
	struct VC_SERVICE_BUFFER_VC_T buffer_vc;
	int err;
	int i;

	if (num_buffers * sizeof(struct VC_SERVICE_BUFFER_USER_T) > len) {
		dev_warn(dev, "invalid message (num_buffers %d, len %zu)\n",
				num_buffers, len);
		return -EINVAL;
	}

	for (i = 0; i < num_buffers; i++) {
		int id;
		struct buffer_idr_val *val;
		size_t offset;

		offset = len - (num_buffers - i)
				* sizeof(struct VC_SERVICE_BUFFER_USER_T);
		memcpy(&buffer_user, &msg[offset], sizeof(buffer_user));

		dev_dbg(dev, "%s: fd=%d size=%d reserved=%d\n", __func__,
			buffer_user.fd, buffer_user.size,
			buffer_user.reserved);

		/*
		 * Store the fd and handle, for use when processing
		 * UNMAP_BUFFERS messages
		 */
		val = kmalloc(sizeof(*val), GFP_KERNEL);
		if (!val)
			return -ENOMEM;
		val->fd = buffer_user.fd;
		val->handle = NULL;

		/* Insert into the idr */
		/* TODO: use idr_alloc() here, when porting to kernel 3.9+ */
		do {
			if (!idr_pre_get(&client->buffer_idr, GFP_KERNEL)) {
				kfree(val);
				return -ENOMEM;
			}
			spin_lock(&client->buffer_idr_lock);
			err = idr_get_new_above(&client->buffer_idr, val, 1,
					&id);
			spin_unlock(&client->buffer_idr_lock);
		} while (err == -EAGAIN);
		if (err) {
			dev_err(dev, "%s: idr_get_new failed (%d)", __func__,
					err);
			kfree(val);
			return err;
		}

		buffer_vc.kernel_id = id;

		/*
		 * Since we don't have ion yet, hack it by passing the VC
		 * mem handle through buffer_user.fd into buffer_vc.addr
		 */
		buffer_vc.addr = buffer_user.fd;
		buffer_vc.size = buffer_user.size;

		/*
		 * NOTE: Since this code is still using vcsm, it probably
		 * ought to acquire a reference to the VC handle, else the
		 * handle we're copying into the message here might get freed
		 * before VC has acquired it. But we're already trusting the
		 * client not to pass invalid handles, so trusting it to not
		 * free the handle too early is not making the situation any
		 * worse.
		 */

		memcpy(&msg[offset], &buffer_vc, sizeof(buffer_vc));
	}
	return 0;
}

static int translate_buffers_to_user_and_unmap(struct client *client,
					       int num_buffers,
					       char *msg, size_t len)
{
	struct device *dev = &client->dev->rpdev->dev;
	struct VC_SERVICE_BUFFER_USER_T buffer_user;
	struct VC_SERVICE_BUFFER_VC_T buffer_vc;
	int i;

	if (num_buffers * sizeof(struct VC_SERVICE_BUFFER_USER_T) > len) {
		dev_warn(dev, "invalid message (num_buffers %d, len %zu)\n",
				num_buffers, len);
		return -EINVAL;
	}

	for (i = 0; i < num_buffers; i++) {
		struct buffer_idr_val *val;
		size_t offset;

		offset = len - (num_buffers - i)
				* sizeof(struct VC_SERVICE_BUFFER_USER_T);
		memcpy(&buffer_vc, &msg[offset], sizeof(buffer_vc));

		dev_dbg(dev, "%s: addr=%d size=%d id=%d\n",
			__func__, buffer_vc.addr, buffer_vc.size,
			buffer_vc.kernel_id);

		spin_lock(&client->buffer_idr_lock);
		val = idr_find(&client->buffer_idr, buffer_vc.kernel_id);
		if (val) {
			idr_remove(&client->buffer_idr, buffer_vc.kernel_id);
			spin_unlock(&client->buffer_idr_lock);

			dev_dbg(dev, "%s: val=%p fd=%d", __func__,
				val, val->fd);
			buffer_user.fd = val->fd;
			kfree(val);
		} else {
			spin_unlock(&client->buffer_idr_lock);
			dev_warn(dev, "%s: unmap of unknown id %d", __func__,
				 buffer_vc.kernel_id);
			buffer_user.fd = -1;
		}

		buffer_user.size = buffer_vc.size;
		buffer_user.reserved = 0;

		memcpy(&msg[offset], &buffer_user, sizeof(buffer_user));
	}
	return 0;
}

/* Must be called with client->mutex locked */
static void abort_client(struct client *client)
{
	struct device *dev = &client->dev->rpdev->dev;
	dev_dbg(dev, "%s: state=%d", __func__, client->state);

	if (client->state == CLIENT_RELEASING ||
			client->state == CLIENT_RELEASED) {
		/* Already sent RELEASE once, so don't do it again */

	} else if (client->state == CLIENT_STARTED) {
		/*
		 * Haven't sent any messages to VC yet, so we don't need
		 * to ask it to release anything
		 */
		client->state = CLIENT_RELEASED;

		/* Wake readers so they can see the new state */
		wake_up(&client->readq);

	} else {
		/* Ask VC to release this client's resources */
		struct VC_SERVICE_MSG_RELEASE_T msg;
		memset(&msg, 0, sizeof(msg));
		msg.hdr.type = VC_SERVICE_MSG_RELEASE;

		/*
		 * Use trysend instead of send because blocking with the
		 * client mutex held is likely to end in deadlocks
		 */
		rpmsg_trysend_offchannel(client->dev->rpdev,
					 client->ept->addr,
					 client->dev->rpdev->dst,
					 &msg, sizeof(msg));

		/*
		 * TODO: what if trysend fails, or if it succeeds but VC
		 * drops the message? service_release() might get stuck,
		 * resulting in unkillable processes. Maybe resend the
		 * RELEASE at regular intervals, and if VC doesn't respond
		 * within a reasonable time then assume it has crashed and
		 * reboot it?
		 */

		client->state = CLIENT_RELEASING;

		/* Wake readers so they can see the new state */
		wake_up(&client->readq);
	}
}

static void service_cb(struct rpmsg_channel *rpdev, void *data, int len,
		       void *priv, u32 src)
{
	struct device *dev = &rpdev->dev;
	struct client *client = priv;
	struct VC_SERVICE_MSG_HEADER_T hdr;
	char rewrite_msg[VC_SERVICE_MSG_MAX_LENGTH];

	dev_dbg(dev, "%s: src=0x%x data=%p len=%d\n", __func__, src,
			data, len);

	mutex_lock(&client->mutex);

	if (len < sizeof(hdr) || len > VC_SERVICE_MSG_MAX_LENGTH) {
		dev_warn(dev, "received message invalid size (%d bytes)\n",
				len);
		abort_client(client);
		goto out;
	}
	memcpy(&hdr, data, sizeof(hdr));

	dev_dbg(dev, "%s: type=%d\n", __func__, hdr.type);

	if (hdr.type == VC_SERVICE_MSG_OPEN_REPLY) {
		struct VC_SERVICE_MSG_OPEN_REPLY_T msg;

		if (client->state != CLIENT_OPENING) {
			dev_warn(dev, "OPEN_REPLY in incorrect state %d\n",
					client->state);
			abort_client(client);
			goto out;
		}

		if (len != sizeof(msg)) {
			dev_warn(dev, "OPEN_REPLY message wrong size (%d != %zu)\n",
					len, sizeof(msg));
			abort_client(client);
			goto out;
		}

		memcpy(&msg, data, len);
		client->state = CLIENT_OPEN;

	} else if (hdr.type == VC_SERVICE_MSG_RELEASE_REPLY) {
		if (client->state != CLIENT_RELEASING) {
			dev_warn(dev, "RELEASE_REPLY in incorrect state %d\n",
					client->state);
			abort_client(client);
			goto out;
		}
		client->state = CLIENT_RELEASED;

	} else if (hdr.type == VC_SERVICE_MSG_FATAL_ERROR) {
		struct VC_SERVICE_MSG_FATAL_ERROR_T msg;

		if (len != sizeof(msg)) {
			dev_warn(dev, "FATAL_ERROR message wrong size (%d != %zu)\n",
					len, sizeof(msg));
			abort_client(client);
			goto out;
		}

		memcpy(&msg, data, len);
		dev_warn(dev, "FATAL_ERROR reason=%d data=%d",
				msg.reason, msg.data);

		/*
		 * Special case: if we're RELEASING and get an UNKNOWN_CLIENT,
		 * that means either the MSG_OPEN was not received by VC, or
		 * the MSG_RELEASE has been received twice. In either case,
		 * VC isn't holding any client resources so we can just
		 * switch to RELEASED immediately. (This is necessary because
		 * if we receive an error while in OPENING, we can't tell
		 * whether the error occurred before or after VC processed
		 * the MSG_OPEN, so we have to unconditionally send the
		 * MSG_RELEASE and then wait for either MSG_RELEASE_REPLY or
		 * this error.)
		 */
		if (client->state == CLIENT_RELEASING && msg.reason ==
				VC_SERVICE_ERROR_UNKNOWN_CLIENT) {
			client->state = CLIENT_RELEASED;
		}

	} else if (hdr.type == VC_SERVICE_MSG_UNMAP_BUFFERS) {
		/* Copy from shared memory into a writable buffer */
		memcpy(&rewrite_msg, data, len);

		if (translate_buffers_to_user_and_unmap(client,
				hdr.num_buffers, rewrite_msg, len)) {
			abort_client(client);
			goto out;
		}

		/* Send the translated message to the client */
		data = rewrite_msg;

	} else if (hdr.type <= VC_SERVICE_MSG_MAX) {
		dev_warn(dev, "unrecognised reserved reply %d", hdr.type);
		abort_client(client);
		goto out;

	} else {
		if (client->state != CLIENT_OPEN) {
			dev_warn(dev, "received message %d in non-OPEN state %d\n",
					hdr.type, client->state);
			abort_client(client);
			goto out;
		}
	}

	if (kfifo_in(&client->fifo, data, len) != len) {
		dev_warn(dev, "message fifo overflowed (client too slow?)\n");
		abort_client(client);
		goto out;
	}

out:
	mutex_unlock(&client->mutex);
	wake_up(&client->readq);

	return;
}

static int service_open(struct inode *inode, struct file *filp)
{
	int ret;
	struct device *dev;
	struct client *client;
	struct service_dev *vcdev;

	vcdev = container_of(inode->i_cdev, struct service_dev, cdev);
	dev = &vcdev->rpdev->dev;

	dev_dbg(dev, "%s\n", __func__);

	ret = vc_suspend_use(dev);
	if (ret)
		goto fail;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto fail_after_suspend;
	}

	mutex_init(&client->mutex);
	client->dev = vcdev;
	client->state = CLIENT_STARTED;
	init_waitqueue_head(&client->readq);

	idr_init(&client->buffer_idr);
	spin_lock_init(&client->buffer_idr_lock);

	ret = kfifo_alloc(&client->fifo, CLIENT_FIFO_SIZE, GFP_KERNEL);
	if (ret)
		goto fail_after_client;

	client->ept = rpmsg_create_ept(vcdev->rpdev, service_cb, client,
				       RPMSG_ADDR_ANY);
	if (!client->ept) {
		dev_err(dev, "%s: rpmsg_create_ept failed\n", __func__);
		ret = -ENOMEM;
		goto fail_after_client;
	}

	filp->private_data = client;

	dev_dbg(dev, "opened endpoint 0x%x\n", client->ept->addr);

	return 0;

fail_after_client:
	if (client->ept)
		rpmsg_destroy_ept(client->ept);
	kfifo_free(&client->fifo);
	idr_destroy(&client->buffer_idr);
	mutex_destroy(&client->mutex);
	kfree(client);
fail_after_suspend:
	vc_suspend_release(dev);
fail:
	return ret;
}

static int service_release(struct inode *inode, struct file *filp)
{
	struct client *client = filp->private_data;
	struct device *dev = &client->dev->rpdev->dev;

	/*
	 * The kernel guarantees release won't be called while any
	 * read/write calls are active, so we just need to be careful
	 * about concurrency with service_cb.
	 */

	dev_dbg(dev, "%s\n", __func__);

	mutex_lock(&client->mutex);

	abort_client(client);

	dev_dbg(dev, "%s: waiting for RELEASE_REPLY\n", __func__);

	/*
	 * Wait for VC to acknowledge the RELEASE message (else we might
	 * reuse the endpoint address for a subsequent client, and it'll
	 * receive messages that were meant for this client; and we need
	 * to give VC a chance to ask the kernel to unmap buffers)
	 */
	while (client->state != CLIENT_RELEASED) {
		mutex_unlock(&client->mutex);
		wait_event(client->readq, client->state == CLIENT_RELEASED);
		mutex_lock(&client->mutex);
	}

	dev_dbg(dev, "%s: got RELEASE_REPLY\n", __func__);

	/*
	 * Unlock client before rpmsg_destroy_ept, else it may deadlock
	 * with ept->cb_lock
	 */
	mutex_unlock(&client->mutex);

	/*
	 * Destroy the endpoint - the callback will not be running (and
	 * will not be started again) after rpmsg_destroy_ept returns,
	 * so we can safely destroy client
	 */
	rpmsg_destroy_ept(client->ept);

	kfifo_free(&client->fifo);
	idr_destroy(&client->buffer_idr);
	mutex_destroy(&client->mutex);
	kfree(client);
	vc_suspend_release(dev);

	return 0;
}

static ssize_t service_read(struct file *filp, char __user *buf,
			    size_t count, loff_t *offp)
{
	struct client *client = filp->private_data;
	struct device *dev = &client->dev->rpdev->dev;
	unsigned int copied;
	int ret;

	dev_dbg(dev, "%s: buf=%p count=%zu\n", __func__, buf, count);

	if (mutex_lock_interruptible(&client->mutex))
		return -ERESTARTSYS;

	/*
	 * Wait until the fifo has some data to read, or the client is in
	 * an error state (RELEASING/RELEASED)
	 */
	while (client->state <= CLIENT_OPEN &&
			kfifo_is_empty(&client->fifo)) {
		mutex_unlock(&client->mutex);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(client->readq,
			!(client->state <= CLIENT_OPEN &&
					kfifo_is_empty(&client->fifo))))
			return -ERESTARTSYS;
		if (mutex_lock_interruptible(&client->mutex))
			return -ERESTARTSYS;
	}

	if (client->state <= CLIENT_OPEN) {
		ret = kfifo_to_user(&client->fifo, buf, count, &copied);
	} else {
		dev_warn(dev, "read() with invalid client state %d\n",
				client->state);
		ret = -EIO;
	}

	mutex_unlock(&client->mutex);

	return ret ? ret : copied;
}

static void inject_fatal_error(struct client *client, int32_t reason,
			       int32_t data)
{
	struct device *dev = &client->dev->rpdev->dev;
	struct VC_SERVICE_MSG_FATAL_ERROR_T msg;

	memset(&msg, 0, sizeof(msg));
	msg.hdr.type = VC_SERVICE_MSG_FATAL_ERROR;
	msg.reason = reason;
	msg.data = data;

	if (kfifo_in(&client->fifo, &msg, sizeof(msg)) != sizeof(msg)) {
		dev_warn(dev, "message fifo overflowed for fatal error\n");
		abort_client(client);
		return;
	}
	wake_up(&client->readq);
}

static int intercept_msg_open(struct client *client, char *msg)
{
	struct device *dev = &client->dev->rpdev->dev;
	struct VC_SERVICE_MSG_OPEN_T *msg_open = (void *)msg;

	if (msg_open->version < VC_RPMSG_SERVICE_VERSION_MIN) {
		dev_warn(dev, "vc_rpmsg_service: Client protocol version %d too old for this kernel (version %d, min %d)",
				msg_open->version,
				VC_RPMSG_SERVICE_VERSION,
				VC_RPMSG_SERVICE_VERSION_MIN);
		return -EINVAL;
	}

	if (VC_RPMSG_SERVICE_VERSION < msg_open->version_min) {
		dev_warn(dev, "vc_rpmsg_service: Kernel protocol version %d too old for this client (version %d, min %d)",
				VC_RPMSG_SERVICE_VERSION,
				msg_open->version,
				msg_open->version_min);
		return -EINVAL;
	}

	msg_open->version = min(msg_open->version,
			VC_RPMSG_SERVICE_VERSION);
	msg_open->version_min = max(msg_open->version_min,
			VC_RPMSG_SERVICE_VERSION_MIN);

	return 0;
}

static ssize_t service_write(struct file *filp, const char __user *buf,
			     size_t count, loff_t *f_pos)
{
	struct client *client = filp->private_data;
	struct device *dev = &client->dev->rpdev->dev;
	struct VC_SERVICE_MSG_HEADER_T hdr;
	char msg[VC_SERVICE_MSG_MAX_LENGTH];
	int err;

	dev_dbg(dev, "%s state=%d buf=%p count=%zu\n", __func__,
		client->state, buf, count);

	if (count < sizeof(hdr) || count > sizeof(msg))
		return -EINVAL;

	if (copy_from_user(&msg, buf, count))
		return -EFAULT;

	memcpy(&hdr, msg, sizeof(hdr));

	dev_dbg(dev, "%s type=%d\n", __func__, hdr.type);

	if (mutex_lock_interruptible(&client->mutex))
		return -ERESTARTSYS;

	/* If the connection was aborted, alert the client immediately */
	if (client->state > CLIENT_OPEN) {
		mutex_unlock(&client->mutex);
		return -EIO;
	}

	if (hdr.type == VC_SERVICE_MSG_OPEN &&
			client->state == CLIENT_STARTED) {

		err = intercept_msg_open(client, msg);
		if (err) {
			/*
			 * Incompatible version - we want to report the
			 * error nicely to the client (since the user
			 * probably needs to be told to update their code),
			 * so pretend that the write() succeeded but inject
			 * an error message into the client fifo
			 */
			inject_fatal_error(client,
					VC_SERVICE_ERROR_INCOMPATIBLE_VERSION,
					0);
			mutex_unlock(&client->mutex);
			return count;
		}

		client->state = CLIENT_OPENING;

	} else if (client->state == CLIENT_STARTED) {
		/* Only OPEN is allowed in STARTED */
		dev_warn(dev, "attempting to send message %d in state STARTED",
				hdr.type);
		mutex_unlock(&client->mutex);
		return -EBADFD;

	} else if (hdr.type <= VC_SERVICE_MSG_MAX) {
		/* Clients can't send any reserved messages except OPEN */
		dev_warn(dev, "attempting to send reserved message %d",
				hdr.type);
		mutex_unlock(&client->mutex);
		return -EINVAL;
	}

	mutex_unlock(&client->mutex);

	err = translate_buffers_to_vc(client, hdr.num_buffers, msg, count);
	if (err)
		return err;

	err = rpmsg_send_offchannel(client->dev->rpdev,
			client->ept->addr, client->dev->rpdev->dst,
			&msg, count);
	if (err) {
		dev_err(dev, "rpmsg_send failed: %d\n", err);
		return err;
	}

	return count;
}

static unsigned int service_poll(struct file *filp, poll_table *wait)
{
	struct client *client = filp->private_data;
	unsigned int mask;

	mutex_lock(&client->mutex);

	poll_wait(filp, &client->readq, wait);

	mask = POLLOUT | POLLWRNORM;

	if (!kfifo_is_empty(&client->fifo))
		mask |= POLLIN | POLLRDNORM;

	if (client->state > CLIENT_OPEN)
		mask |= POLLERR;

	mutex_unlock(&client->mutex);

	return mask;
}

static const struct file_operations service_fops = {
	.owner = THIS_MODULE,
	.open = service_open,
	.release = service_release,
	.read = service_read,
	.write = service_write,
	.poll = service_poll,
};

struct vc_service_driver {
	struct service_dev dev;
	struct rpmsg_driver drv;
	char name[32];
	struct list_head list;
};

static int service_probe(struct rpmsg_channel *rpdev)
{
	int err;
	struct device *chardev;
	struct device *dev = &rpdev->dev;
	struct rpmsg_driver *rpdrv;
	struct vc_service_driver *svcdrv;
	struct service_dev *svcdev;

	rpdrv = container_of(rpdev->dev.driver, struct rpmsg_driver, drv);
	svcdrv = container_of(rpdrv, struct vc_service_driver, drv);
	svcdev = &svcdrv->dev;

	dev_info(dev, "%s: set up new channel 0x%x -> 0x%x\n",
			__func__, rpdev->src, rpdev->dst);

	svcdev->rpdev = rpdev;

	err = alloc_chrdev_region(&svcdev->devnum, 0, 1, svcdrv->name);
	if (err < 0) {
		dev_err(dev, "%s: can't get device number\n", __func__);
		goto fail;
	}

	cdev_init(&svcdev->cdev, &service_fops);
	err = cdev_add(&svcdev->cdev, svcdev->devnum, 1);
	if (err < 0) {
		dev_err(dev, "%s: cdev_add failed\n", __func__);
		goto fail_after_chrdev_region;
	}

	svcdev->class = class_create(THIS_MODULE, svcdrv->name);
	if (IS_ERR(svcdev->class)) {
		err = PTR_ERR(svcdev->class);
		dev_err(dev, "%s: class_create failed\n", __func__);
		goto fail_after_cdev;
	}

	chardev = device_create(svcdev->class, NULL, svcdev->devnum, NULL,
			svcdrv->name);
	if (IS_ERR(chardev)) {
		err = PTR_ERR(chardev);
		dev_err(dev, "%s: device_create failed\n", __func__);
		goto fail_after_class;
	}

	return 0;

fail_after_class:
	class_destroy(svcdev->class);
fail_after_cdev:
	cdev_del(&svcdev->cdev);
fail_after_chrdev_region:
	unregister_chrdev_region(svcdev->devnum, 1);
fail:
	return err;
}

static void service_remove(struct rpmsg_channel *rpdev)
{
	struct device *dev = &rpdev->dev;
	struct rpmsg_driver *rpdrv;
	struct vc_service_driver *svcdrv;
	struct service_dev *svcdev;

	rpdrv = container_of(rpdev->dev.driver, struct rpmsg_driver, drv);
	svcdrv = container_of(rpdrv, struct vc_service_driver, drv);
	svcdev = &svcdrv->dev;

	dev_dbg(dev, "%s\n", __func__);

	device_destroy(svcdev->class, svcdev->devnum);
	class_destroy(svcdev->class);
	cdev_del(&svcdev->cdev);
	unregister_chrdev_region(svcdev->devnum, 1);
}

/*
 * The "hostexport" mechanism allows VC to specify which services should
 * be exported by the host as char devices, so new services can be added
 * without rebuilding the kernel.
 *
 * We register an rpmsg driver that is probed when VC announces the
 * hostexport service, then send a query message, and for every response
 * message we set up a new driver for that service.
 */

/* Message definitions (must be kept in sync with VC): */

#define HOSTEXPORT_NAME_LEN 32

enum HOSTEXPORT_MSG_TYPE {
	HOSTEXPORT_MSG_QUERY,
	HOSTEXPORT_MSG_RESPONSE,
};

struct HOSTEXPORT_MSG_QUERY_T {
	uint32_t type;
};

struct HOSTEXPORT_MSG_RESPONSE_T {
	uint32_t type;
	char service_name[RPMSG_NAME_SIZE];
	char chardev_name[HOSTEXPORT_NAME_LEN];
};


static LIST_HEAD(hostexport_services);

static int hostexport_probe(struct rpmsg_channel *rpdev)
{
	int err;
	struct HOSTEXPORT_MSG_QUERY_T msg;
	msg.type = HOSTEXPORT_MSG_QUERY;
	err = rpmsg_send(rpdev, &msg, sizeof(msg));
	return err;
}

static void hostexport_remove(struct rpmsg_channel *rpdev)
{
}

static int hostexport_create_service(struct rpmsg_channel *rpdev,
				     const char *id, const char *name)
{
	int err;
	struct rpmsg_device_id *id_table = NULL;
	struct vc_service_driver *service = NULL;

	/* Allocate one entry plus a NULL-terminator entry */
	id_table = kzalloc(sizeof(*id_table) * 2, GFP_KERNEL);
	if (!id_table) {
		err = -ENOMEM;
		goto fail;
	}

	service = kzalloc(sizeof(*service), GFP_KERNEL);
	if (!service) {
		err = -ENOMEM;
		goto fail;
	}

	INIT_LIST_HEAD(&service->list);
	strlcpy(id_table[0].name, id, sizeof(id_table[0].name));
	strlcpy(service->name, name, sizeof(service->name));
	service->drv.drv.name = service->name;
	service->drv.drv.owner = THIS_MODULE;
	service->drv.id_table = id_table;
	service->drv.probe = service_probe;
	service->drv.callback = service_cb;
	service->drv.remove = service_remove;

	err = register_rpmsg_driver(&service->drv);
	if (err) {
		dev_err(&rpdev->dev, "%s: register_rpmsg_driver failed\n",
				__func__);
		goto fail;
	}

	list_add(&service->list, &hostexport_services);

	return 0;

fail:
	kfree(service);
	kfree(id_table);
	return err;
}

static void hostexport_cb(struct rpmsg_channel *rpdev, void *data, int len,
			  void *priv, u32 src)

{
	struct device *dev = &rpdev->dev;
	struct HOSTEXPORT_MSG_RESPONSE_T *msg;
	int err;

	if (len != sizeof(struct HOSTEXPORT_MSG_RESPONSE_T)) {
		dev_err(&rpdev->dev, "unexpected message length %d\n", len);
		return;
	}

	msg = data;
	if (msg->type != HOSTEXPORT_MSG_RESPONSE) {
		dev_err(&rpdev->dev, "unexpected message type %d\n",
				msg->type);
		return;
	}

	err = hostexport_create_service(rpdev, msg->service_name,
			msg->chardev_name);
	if (err < 0) {
		dev_err(dev, "failed to export service \"%s\" as \"%s\"\n",
				msg->service_name, msg->chardev_name);
	} else {
		dev_info(dev, "exported service \"%s\" as \"%s\"\n",
				msg->service_name, msg->chardev_name);
	}
}

static struct rpmsg_device_id hostexport_id_table[] = {
	{ .name	= "hostexport" },
	{ },
};

static struct rpmsg_driver hostexport_driver = {
	.drv.name	= "vc-hostexport",
	.drv.owner	= THIS_MODULE,
	.id_table	= hostexport_id_table,
	.probe		= hostexport_probe,
	.callback	= hostexport_cb,
	.remove		= hostexport_remove,
};

static int __init service_init(void)
{
	int err;

	err = register_rpmsg_driver(&hostexport_driver);
	if (err) {
		pr_err("%s: register_rpmsg_driver failed\n", __func__);
		return err;
	}

	return 0;
}

static void __exit service_exit(void)
{
	struct vc_service_driver *service, *n;

	list_for_each_entry_safe(service, n, &hostexport_services, list) {
		list_del(&service->list);
		unregister_rpmsg_driver(&service->drv);
		kfree(service->drv.id_table);
		kfree(service);
	}

	unregister_rpmsg_driver(&hostexport_driver);
}

module_init(service_init);
module_exit(service_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Broadcom Corporation");
