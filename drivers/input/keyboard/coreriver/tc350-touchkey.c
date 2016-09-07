/*
 * CORERIVER TOUCHCORE touchkey driver
 *
 * Copyright (C) 2012 Samsung Electronics Co.Ltd
 * Author: Taeyoon Yoon <tyoony.yoon@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/leds.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/wakelock.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>
#include <linux/regulator/consumer.h>
#include "tc350-touchkey.h"
#ifdef CONFIG_SLEEP_MONITOR
#include <linux/power/sleep_monitor.h>
#endif

#define TC300K_FW_BUILTIN_PATH	"coreriver"
#define TC300K_FW_IN_SDCARD_PATH	"/opt/usr/media/"

#define TC300K_POWERON_DELAY		300
#define TC300K_KEY_INDEX_MASK		0x07
#define TC300K_KEY_PRESS_MASK		0x08
/* registers */
#define TC300K_KEYCODE			0x00
#define TC300K_FWVER			0x01
#define TC300K_MDVER			0x02
#define TC300K_MODE			0x03
#define TC300K_CHECKS_H		0x04
#define TC300K_CHECKS_L		0x05

#define TC300K_1KEY_DATA		0x10
#define TC300K_2KEY_DATA		0x18
#define TC300K_3KEY_DATA		0x20
#define TC300K_4KEY_DATA		0x28

#define TC300K_THRES_H_OFFSET		0x00
#define TC300K_THRES_L_OFFSET		0x01
#define TC300K_CH_PCK_H_OFFSET	0x02
#define TC300K_CH_PCK_L_OFFSET	0x03
#define TC300K_DIFF_H_OFFSET		0x04
#define TC300K_DIFF_L_OFFSET		0x05
#define TC300K_RAW_H_OFFSET		0x06
#define TC300K_RAW_L_OFFSET		0x07

/* command */
#define TC300K_CMD_ADDR		0x00
#define TC300K_CMD_LED_ON		0x10
#define TC300K_CMD_LED_OFF		0x20
#define TC300K_CMD_GLOVE_ON		0x30
#define TC300K_CMD_GLOVE_OFF		0x40
#define TC300K_CMD_FAC_ON		0x50
#define TC300K_CMD_FAC_OFF		0x60
#define TC300K_CMD_CAL_CHECKSUM	0x70
#define TC300K_CMD_DELAY		50

/* ISP command */
#define TC300K_CSYNC1			0xA3
#define TC300K_CSYNC2			0xAC
#define TC300K_CSYNC3			0xA5
#define TC300K_CCFG			0x92
#define TC300K_PRDATA			0x81
#define TC300K_PEDATA			0x82
#define TC300K_PWDATA			0x83
#define TC300K_PECHIP			0x8A
#define TC300K_PEDISC			0xB0
#define TC300K_LDDATA			0xB2
#define TC300K_LDMODE			0xB8
#define TC300K_RDDATA			0xB9
#define TC300K_PCRST			0xB4
#define TC300K_PCRED			0xB5
#define TC300K_PCINC			0xB6
#define TC300K_RDPCH			0xBD

/* ISP delay */
#define TC300K_TSYNC1			300	/* us */
#define TC300K_TSYNC2			50	/* 1ms~50ms */
#define TC300K_TSYNC3			100	/* us */
#define TC300K_TDLY1			1	/* us */
#define TC300K_TDLY2			2	/* us */
#define TC300K_TFERASE			10	/* ms */
#define TC300K_TPROG			20	/* us */

#define TC300K_CHECKSUM_DELAY		500
#define TO_STRING(x) #x

#define TC300K_RETRY_CNT		3

#define TC300K_KEY_PRESS		1
#define TC300K_KEY_RELEASE		0

#define TC300K_INVALID_VER		0xff

#define SEC_DEV_TOUCHKEY_MAJOR	1
#define SEC_DEV_TOUCHKEY_MINOR	0

enum {
	FW_BUILT_IN = 0,
	FW_IN_SDCARD,
};

enum {
	HAVE_LATEST_FW = 1,
	FW_UPDATE_RUNNING,
};

enum {
	DOWNLOADING = 1,
	FAIL,
	PASS,
};

struct fdata_struct {
	struct device	*dummy_dev;
	u8		fw_flash_status;
	u8		fw_update_skip;
};

struct fw_image {
	u8 hdr_ver;
	u8 hdr_len;
	u16 first_fw_ver;
	u16 second_fw_ver;
	u16 third_ver;
	u32 fw_len;
	u16 checksum;
	u16 alignment_dummy;
	u8 data[0];
} __attribute__ ((packed));

struct tsk_event_val {
	u16	tsk_bitmap;
	u8	tsk_status;
	int	tsk_keycode;
	char*	tsk_keyname;
};

struct tc300k_data {
	struct i2c_client	*client;
	struct input_dev	*input_dev;
	struct tc300k_platform_data	*pdata;
	struct mutex		lock;
	struct fw_image		*fw_img;
	struct pinctrl *pinctrl;
	struct fdata_struct	*fdata;
	struct wake_lock	fw_wake_lock;
	struct regulator *vcc_en;
	struct regulator *vdd_led;
	struct tsk_event_val *tsk_ev_val;
	const struct firmware	*fw;
	char	phys[32];
	int	num_key;
	int	*keycodes;
	int	ic_fw_ver;
	u32	scl;
	u32	sda;
	u16	threhold;
	u8	cur_fw_path;
	u8	fw_flash_state;
	u8	suspend_type;
	bool	counting_timer;
	bool	enabled;
	bool	glove_mode;
	bool	factory_mode;
	bool	led_on;
	u32	release_cnt;
};

struct tsk_event_val tsk_ev[TC300K_MAX_KEY*2] =
{
	{0x01, TC300K_KEY_PRESS, KEY_PHONE, "MENU_KEY"},
	{0x02, TC300K_KEY_PRESS, KEY_BACK, "BACK_KEY"},
	{0x10, TC300K_KEY_RELEASE, KEY_PHONE, "MENU_KEY"},
	{0x20, TC300K_KEY_RELEASE, KEY_BACK, "BACK_KEY"},
};

#ifdef CONFIG_PM_SLEEP
static int tc300k_input_open(struct input_dev *dev);
static void tc300k_input_close(struct input_dev *dev);
#endif
extern struct class *sec_class;

static int tkey_pinctrl_configure(struct tc300k_data *data, bool active)
{
#if 0
	struct pinctrl_state *set_state_i2c;
	int retval;

	dev_info(&data->client->dev, "%s: %s\n", __func__, active ? "ACTIVE" : "SUSPEND");

	if (active) {
		set_state_i2c =
			pinctrl_lookup_state(data->pinctrl,
				"tkey_gpio_active");
		if (IS_ERR(set_state_i2c)) {
			dev_err(&data->client->dev, "%s: cannot get pinctrl(i2c) active state\n", __func__);
			return PTR_ERR(set_state_i2c);
		}
	} else {
		set_state_i2c =
			pinctrl_lookup_state(data->pinctrl,
					"tkey_gpio_suspend");
		if (IS_ERR(set_state_i2c)) {
			dev_err(&data->client->dev, "%s: cannot get pinctrl(i2c) sleep state\n", __func__);
			return PTR_ERR(set_state_i2c);
		}
	}

	retval = pinctrl_select_state(data->pinctrl, set_state_i2c);
	if (retval) {
		dev_err(&data->client->dev, "%s: cannot set pinctrl(i2c) %s state\n",
			__func__, active ? "active" : "suspend");
		return retval;
	}

	if (active) {
		gpio_direction_input(data->pdata->gpio_sda);
		gpio_direction_input(data->pdata->gpio_scl);
		gpio_direction_input(data->pdata->gpio_int);
	}
#endif
	return 0;

}

static void tc300k_gpio_request(struct tc300k_data *data)
{
	struct tc300k_platform_data	*pdata = data->pdata;
	struct i2c_client *client = data->client;
	int ret = 0;

	ret = gpio_request(pdata->gpio_en, "touchkey_en_gpio");
	if (ret)
		dev_err(&client->dev, "%s: unable to request touchkey_en_gpio[%d]\n",
			__func__, pdata->gpio_en);
	else
		dev_dbg(&client->dev, "%s: request touchkey_en_gpio[%d]\n",
			__func__, pdata->gpio_en);


	ret = gpio_request(pdata->gpio_int, "touchkey_irq");
	if (ret)
		dev_err(&client->dev, "%s: unable to request touchkey_irq [%d]\n",
			__func__, pdata->gpio_int);
	else
		dev_dbg(&client->dev, "%s: request touchkey_irq [%d]\n",
			__func__, pdata->gpio_int);

	ret = gpio_request(pdata->gpio_sda, "touchkey_sda");
	if (ret)
		dev_err(&client->dev, "%s: unable to request touchkey_sda [%d]\n",
			__func__, pdata->gpio_sda);
	else
		dev_dbg(&client->dev, "%s: request touchkey_sda [%d]\n",
			__func__, pdata->gpio_sda);

	ret = gpio_request(pdata->gpio_sda, "touchkey_scl");
	if (ret)
		dev_err(&client->dev, "%s: unable to request touchkey_scl [%d]\n",
			__func__, pdata->gpio_scl);
	else
		dev_dbg(&client->dev, "%s: request touchkey_scl [%d]\n",
			__func__, pdata->gpio_scl);

	if ((int)(pdata->gpio_2p8_en) > 0) {
	ret = gpio_request(pdata->gpio_2p8_en, "touchkey_en_gpio2p8");
		if (ret)
		dev_err(&client->dev, "%s: unable to request touchkey_en_gpio2p8[%d]\n",
			__func__, pdata->gpio_2p8_en);
		else
		dev_dbg(&client->dev, "%s: request touchkey_en_gpio2p8[%d]\n",
			__func__, pdata->gpio_2p8_en);
	}

	ret = gpio_direction_input(pdata->gpio_sda);
	if (ret)
		dev_err(&client->dev, "%s: unable to change direction touchkey_sda [%d]\n",
			__func__, pdata->gpio_sda);
	else
		dev_dbg(&client->dev, "%s: change direction touchkey_sda [%d]\n",
			__func__, pdata->gpio_sda);

	ret = gpio_direction_input(pdata->gpio_scl);
	if (ret)
		dev_err(&client->dev, "%s: unable to change direction touchkey_scl [%d]\n",
			__func__, pdata->gpio_sda);
	else
		dev_dbg(&client->dev, "%s: change direction touchkey_scl [%d]\n",
			__func__, pdata->gpio_scl);

	ret = gpio_direction_input(pdata->gpio_int);
	if (ret)
		dev_err(&client->dev, "%s: unable to change direction touchkey_int [%d]\n",
			__func__, pdata->gpio_int);
	else
		dev_dbg(&client->dev, "%s: change direction touchkey_int [%d]\n",
			__func__, pdata->gpio_int);

	ret = gpio_direction_output(pdata->gpio_en, 0);
	if (ret)
		dev_err(&client->dev, "%s: unable to change direction touchkey_en [%d]\n",
			__func__, pdata->gpio_en);
	else
		dev_dbg(&client->dev, "%s: change direction touchkey_en [%d]\n",
			__func__, pdata->gpio_en);

	if ((int)(pdata->gpio_2p8_en) > 0 ) {
		ret = gpio_direction_output(pdata->gpio_2p8_en, 0);
		if (ret)
			dev_err(&client->dev, "%s: unable to change direction touchkey_2p8_en [%d]\n",
				__func__, pdata->gpio_2p8_en);
		else
			dev_dbg(&client->dev, "%s: change direction touchkey_2p8_en [%d]\n",
				__func__, pdata->gpio_2p8_en);
	}
}

void tc300k_power(struct tc300k_data *data, int onoff)
{
	struct i2c_client *client = data->client;

	if (onoff)
		gpio_direction_output(data->pdata->gpio_en, 1);
	else
		gpio_direction_output(data->pdata->gpio_en, 0);

	if ((int)(data->pdata->gpio_2p8_en) > 0 )
		gpio_direction_output(data->pdata->gpio_2p8_en, onoff);

	dev_info(&client->dev, "%s: [%s]\n",__func__, onoff ? "ON" : "OFF");
}

void tc300k_led_power(struct tc300k_data *data, bool onoff)
{
	return;

	if (onoff)
		pr_info("%sTKEY_LED 3.3V[vdd_led] on is finished.\n",__func__);
	else
		pr_info("%sTKEY_LED 3.3V[vdd_led] off is finished\n",__func__);
}

static int tc300k_get_module_ver(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int retries = 3;
	int module_ver = 0;

read_module_version:
	module_ver = i2c_smbus_read_byte_data(client, TC300K_MDVER);
	if (module_ver < 0) {
		dev_err(&client->dev,
			"%s: failed to read IC module ver [%d][%d]\n", __func__,
			module_ver, retries);
		if (retries-- > 0) {
			tc300k_power(data,0);
			msleep(TC300K_POWERON_DELAY);
			tc300k_power(data,1);
			msleep(TC300K_POWERON_DELAY);
			goto read_module_version;
		}
	}

	return module_ver;
}

static int tc300k_get_fw_ver(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int ver = 0;
	int retries = 2;

read_version:
	ver = i2c_smbus_read_byte_data(client, TC300K_FWVER);
	if (ver < 0) {
		dev_err(&client->dev,
			"%s : failed to read IC fw ver. [%d][%d]\n",
			__func__, ver, retries);
		if (retries--) {
			tc300k_power(data,0);
			msleep(TC300K_POWERON_DELAY);
			tc300k_power(data,1);
			msleep(TC300K_POWERON_DELAY);
			goto read_version;
		}
	}

	if (retries)
		data->ic_fw_ver= ver;
	else
		dev_err(&client->dev, "%s : failed to get IC fw ver.\n", __func__);

	return ver;
}

static inline void setsda(struct tc300k_data *data, int state)
{
	if (state)
		gpio_direction_output(data->pdata->gpio_sda, 1);
	else
		gpio_direction_output(data->pdata->gpio_sda, 0);
}

static inline void setscl(struct tc300k_data *data, int state)
{
	if (state)
		gpio_direction_output(data->pdata->gpio_scl, 1);
	else
		gpio_direction_output(data->pdata->gpio_scl, 0);
}

static inline int getsda(struct tc300k_data *data)
{
	gpio_direction_input(data->pdata->gpio_sda);

	return gpio_get_value(data->pdata->gpio_sda);
}

static inline int getscl(struct tc300k_data *data)
{
	return gpio_get_value(data->pdata->gpio_scl);
}

static void send_9bit(struct tc300k_data *data, u8 buff)
{
	int i;

	setscl(data, 1);
	setsda(data, 0);
	setscl(data, 0);

	for (i = 0; i < 8; i++) {
		setscl(data, 1);
		setsda(data, (buff >> i) & 0x01);
		setscl(data, 0);
	}

	setsda(data, 0);
}

static u8 wait_9bit(struct tc300k_data *data)
{
	int i;
	int buf;
	u8 send_buf = 0;

	getsda(data);
	setscl(data, 1);
	setscl(data, 0);

	for (i = 0; i < 8; i++) {
		setscl(data, 1);
		buf = getsda(data);
		setscl(data, 0);
		send_buf |= (buf & 0x01) << i;
	}
	setsda(data, 0);

	return send_buf;
}

static void tc300k_reset_for_isp(struct tc300k_data *data, bool start)
{
	if (start) {
		tc300k_led_power(data,0);
		gpio_direction_input(data->pdata->gpio_int);
		gpio_direction_output(data->pdata->gpio_scl, 0);
		gpio_direction_output(data->pdata->gpio_sda, 0);
		gpio_direction_output(data->pdata->gpio_int, 0);
		tc300k_power(data,0);
		msleep(100);
		tc300k_power(data,1);
		usleep_range(5000, 6000);
	} else {
		tc300k_led_power(data,0);
		tc300k_power(data,0);
		msleep(100);
		gpio_direction_output(data->pdata->gpio_scl, 1);
		gpio_direction_output(data->pdata->gpio_sda, 1);
		gpio_direction_output(data->pdata->gpio_int, 1);
		usleep_range(10,10);
		tc300k_power(data,1);
		msleep(70);
		tc300k_led_power(data,1);
		gpio_direction_input(data->pdata->gpio_sda);
		gpio_direction_input(data->pdata->gpio_scl);
		gpio_direction_input(data->pdata->gpio_int);
		msleep(300);
	}
}

static void load(struct tc300k_data *data, u8 buff)
{
	send_9bit(data, TC300K_LDDATA);
	udelay(1);
	send_9bit(data, buff);
	udelay(1);
}

static void step(struct tc300k_data *data, u8 buff)
{
	send_9bit(data, TC300K_CCFG);
	udelay(1);
	send_9bit(data, buff);
	udelay(2);
}

static void setpc(struct tc300k_data *data, u16 addr)
{
	u8 buf[4];
	int i;

	buf[0] = 0x02;
	buf[1] = addr >> 8;
	buf[2] = addr & 0xff;
	buf[3] = 0x00;

	for (i = 0; i < 4; i++)
		step(data, buf[i]);
}

static void configure_isp(struct tc300k_data *data)
{
	u8 buf[7];
	int i;

	buf[0] = 0x75;	buf[1] = 0xFC;	buf[2] = 0xAC;
	buf[3] = 0x75;	buf[4] = 0xFC;	buf[5] = 0x35;
	buf[6] = 0x00;

	/* Step(cmd) */
	for (i = 0; i < 7; i++)
		step(data, buf[i]);
}

static int tc300k_erase_fw(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int i;
	u8 state = 0;

	dev_info(&client->dev, "%s\n", __func__);

	tc300k_reset_for_isp(data, true);

	udelay(300);

	/* isp_enable_condition */
	send_9bit(data, TC300K_CSYNC1);
	udelay(10);
	send_9bit(data, TC300K_CSYNC2);
	udelay(10);
	send_9bit(data, TC300K_CSYNC3);
	usleep_range(150, 160);

	state = wait_9bit(data);
	if (state != 0x01) {
		dev_err(&client->dev, "%s isp enable error %d\n",
			__func__, state);
		return -1;
	}

	configure_isp(data);

	/* Full Chip Erase */
	send_9bit(data, TC300K_PCRST);
	udelay(1);
	send_9bit(data, TC300K_PECHIP);
	usleep_range(15000, 15500);

	state = 0;
	for (i = 0; i < 100; i++) {
		udelay(2);
		send_9bit(data, TC300K_CSYNC1);
		udelay(10);
		send_9bit(data, TC300K_CSYNC2);
		udelay(10);
		send_9bit(data, TC300K_CSYNC3);
		usleep_range(150, 160);

		state = wait_9bit(data);
		if ((state & 0x04) == 0x00)
			break;
	}

	if (i >= 100) {
		dev_err(&client->dev, "%s fail\n", __func__);
		return -1;
	}
	dev_info(&client->dev, "%s success\n", __func__);

	return 0;
}

static int tc300k_write_fw(struct tc300k_data *data)
{
	struct input_dev *input_dev = data->input_dev;
	u16 addr = 0;
	u8 code_data;

	dev_info(&input_dev->dev, "%s\n", __func__);

	setpc(data, addr);
	load(data, TC300K_PWDATA);
	send_9bit(data, TC300K_LDMODE);
	udelay(1);

	while (addr < data->fw_img->fw_len) {
		code_data = data->fw_img->data[addr++];
		load(data, code_data);
		usleep_range(20, 21);
	}

	send_9bit(data, TC300K_PEDISC);
	udelay(1);

	return 0;
}


static int tc300k_verify_fw(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	u16 addr = 0;
	u8 code_data;

	dev_info(&client->dev, "%s\n", __func__);

	setpc(data, addr);

	while (addr < data->fw_img->fw_len) {
		send_9bit(data, TC300K_PRDATA);
		udelay(2);
		code_data = wait_9bit(data);
		udelay(1);

		if (code_data != data->fw_img->data[addr++]) {
			dev_err(&client->dev,
				"%s addr : %#x data error (0x%2x)\n",
				__func__, addr - 1, code_data );
			return -1;
		}
	}

	return 0;
}

static int tc300k_crc_check(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int ret;
	u16 checksum;
	u8 checksum_h, checksum_l, cmd;

	dev_info(&client->dev, "%s\n", __func__);

	cmd = TC300K_CMD_CAL_CHECKSUM;
	ret = i2c_smbus_write_byte_data(client, TC300K_CMD_ADDR, cmd);
	if (ret) {
		dev_err(&client->dev, "%s command fail (%d)\n", __func__, ret);
		return ret;
	}

	msleep(TC300K_CHECKSUM_DELAY);

	ret = i2c_smbus_read_byte_data(client, TC300K_CHECKS_H);
	if (ret < 0) {
		dev_err(&client->dev, "%s: failed to read checksum_h (%d)\n",
			__func__, ret);
		return ret;
	}
	checksum_h = ret;

	ret = i2c_smbus_read_byte_data(client, TC300K_CHECKS_L);
	if (ret < 0) {
		dev_err(&client->dev, "%s: failed to read checksum_l (%d)\n",
			__func__, ret);
		return ret;
	}
	checksum_l = ret;

	checksum = (checksum_h << 8) | checksum_l;

	if (data->fw_img->checksum != checksum) {
		dev_err(&client->dev,
			"%s checksum fail - firm checksum(%d),"
			" compute checksum(%d)\n", __func__,
			data->fw_img->checksum, checksum);
		return -1;
	}

	dev_info(&client->dev, "%s success (0x%04x)\n", __func__, checksum);

	return 0;
}

static int tc300k_fw_update(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int verify_retries= TC300K_RETRY_CNT;
	int retries = TC300K_RETRY_CNT;
	int ret =1;

	dev_info(&client->dev, "%s\n", __func__);
	disable_irq(client->irq);

erase_fw:
	ret = tc300k_erase_fw(data);
	if (ret) {
		if (retries--) {
			dev_err(&client->dev, "%s: retry erasing fw (%d)\n",
				 __func__, retries);
			goto erase_fw;
		} else {
			dev_err(&client->dev, "%s: failed erasing fw\n",
				 __func__);
			goto end_tc300k_flash_fw;
		}
	}

	dev_info(&client->dev, "succeed in erasing fw\n");
	retries = TC300K_RETRY_CNT;

write_fw:
	/* Write */
	ret = tc300k_write_fw(data);
	if (ret) {
		if (retries--) {
			dev_err(&client->dev, "%s: retry writing fw (%d)\n",
				__func__, retries);
			goto write_fw;
		} else {
			dev_err(&client->dev, "%s: failed writing fw\n",
				 __func__);
			goto end_tc300k_flash_fw;
		}
	}

	dev_info(&client->dev, "succeed in writing fw\n");

	/* Verify */
	ret = tc300k_verify_fw(data);
	if (ret) {
		if (verify_retries-- > 0) {
			dev_err(&client->dev, "%s: retry verifing fw (%d)\n",
				__func__, verify_retries);
			retries = TC300K_RETRY_CNT;
			goto erase_fw;
		} else {
			dev_err(&client->dev, "%s: failed verifing fw\n",
				 __func__);
			goto end_tc300k_flash_fw;
		}
	}

	dev_info(&client->dev, "succeed in verifing fw\n");

	tc300k_reset_for_isp(data, false);

	dev_info(&client->dev, "%s: fw_ver(%#x)\n",
		__func__, tc300k_get_fw_ver(data));

	ret = tc300k_crc_check(data);
	if (ret) {
		dev_err(&client->dev, "%s: crc check fail (%d)\n",
			__func__, ret);
		goto	end_tc300k_flash_fw;
	}

	data->fdata->fw_flash_status = PASS;

end_tc300k_flash_fw:

	enable_irq(client->irq);
	data->enabled = true;
	return ret;
}

static int load_fw_built_in(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int ret;
	char *fw_name;

	fw_name = kasprintf(GFP_KERNEL, "%s/%s.fw",
		TC300K_FW_BUILTIN_PATH,  data->pdata->fw_name);

//	dev_info(&client->dev, "built in fw file name: [%s]\n",fw_name);
	ret = request_firmware(&data->fw, fw_name, &client->dev);
	if (ret) {
		dev_err(&client->dev,
			"%s: error requesting built-in firmware (%d)\n"
			, __func__, ret);
		goto out;
	}

	data->fw_img = (struct fw_image *)data->fw->data;

	dev_info(&client->dev, "%s: BIN fw version=[0x%02x] size=[%d byte]\n",
		__func__, data->fw_img->first_fw_ver,
		data->fw_img->fw_len);

out:
	kfree(fw_name);
	return ret;
}

static int load_fw_in_sdcard(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	struct tc300k_platform_data *pdata = data->pdata;
	struct file *fp;
	mm_segment_t old_fs;
	long nread;
	int len, ret;

	char *fw_name = kasprintf(GFP_KERNEL, "%s%s.in.fw",
		  TC300K_FW_IN_SDCARD_PATH, pdata->fw_name);

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	fp = filp_open(fw_name, O_RDONLY, S_IRUSR);
	if (IS_ERR(fp)) {
		dev_err(&client->dev, "%s: fail to open fw in %s\n",
			__func__, fw_name);
		ret = -ENOENT;
		goto err_open_fw;
	}
	len = fp->f_path.dentry->d_inode->i_size;

	data->fw_img = kzalloc(len, GFP_KERNEL);
	if (!data->fw_img) {
		dev_err(&client->dev, "%s: fail to alloc mem for fw\n",
			__func__);
		ret = -ENOMEM;
		goto err_alloc;
	}
	nread = vfs_read(fp, (char __user *)data->fw_img, len, &fp->f_pos);

	dev_info(&client->dev, "%s: load fw in internal sd (%ld)\n",
		 __func__, nread);

	ret = 0;

err_alloc:
	filp_close(fp, NULL);
err_open_fw:
	set_fs(old_fs);
	kfree(fw_name);
	return ret;
}

static int tc300k_load_fw(struct tc300k_data *data, u8 fw_path)
{
	struct i2c_client *client = data->client;
	int ret;

	switch (fw_path) {
	case FW_BUILT_IN:
		ret = load_fw_built_in(data);
		break;

	case FW_IN_SDCARD:
		ret = load_fw_in_sdcard(data);
		break;

	default:
		dev_err(&client->dev, "%s: invalid fw path [%d]\n",
			__func__, fw_path);
		return -ENOENT;
	}

	if (ret) {
		dev_err(&client->dev, "%s: fail to load fw in [%d][%d]\n",
			__func__, fw_path, ret);
		return ret;
	}

	return 0;
}

static int tc300k_unload_fw(struct tc300k_data *data, u8 fw_path)
{
	struct i2c_client *client = data->client;

	switch (fw_path) {
	case FW_BUILT_IN:
		release_firmware(data->fw);
		break;

	case FW_IN_SDCARD:
		kfree(data->fw_img);
		break;

	default:
		dev_err(&client->dev, "%s: invalid fw path (%d)\n",
			__func__, fw_path);
		return -ENOENT;
	}

	return 0;
}

static int tc300k_flash_fw(struct tc300k_data *data, u8 fw_path, bool force)
{
	struct i2c_client *client = data->client;
	int ret, fw_ver, module_ver;

	dev_info(&client->dev, "%s\n", __func__);

	ret = tc300k_load_fw(data, fw_path);
	if (ret) {
		dev_err(&client->dev, "fail to load fw (%d)\n", ret);
		return ret;
	}

	data->cur_fw_path = fw_path;
	fw_ver = tc300k_get_fw_ver(data);
	module_ver = tc300k_get_module_ver(data);

	dev_info(&client->dev, "%s: IC fw version=[0x%02x], module_ver=[0x%02x]\n",
			__func__, fw_ver,module_ver);

	if (!data->pdata->firmup) {
		dev_err(&client->dev, "%s: pass firmup, h/w rev not support\n", __func__);
		ret = HAVE_LATEST_FW;
		goto out;
	}

	if (fw_ver == TC300K_INVALID_VER) {
		force = true;
		dev_info(&client->dev,
			"%s: Enable force_update by invalid version.\n",
			__func__);
	}

	if ((fw_ver >= data->fw_img->first_fw_ver) && !force) {
		ret = HAVE_LATEST_FW;
		data->fdata->fw_update_skip = true;
		dev_info(&client->dev,
			"%s: IC aleady have latest firmware.\n", __func__);
		goto out;
	}

	dev_info(&client->dev, "%s: fw update to %#x (from %#x) (%s)\n",
			__func__, data->fw_img->first_fw_ver,
			fw_ver, force ? "force":"version mismatch");

	data->fdata->fw_update_skip = false;

	ret = tc300k_fw_update(data);
	if (ret)
		goto err_fw_update;

	ret = HAVE_LATEST_FW;
err_fw_update:
 out:
	tc300k_unload_fw(data, fw_path);

	return ret;
}

static int tc300k_load_firmware(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int ret;

	ret = tc300k_flash_fw(data, FW_BUILT_IN, false);
	if (ret)
		dev_info(&client->dev, "success to flash fw (%d)\n", ret);
	else
		dev_err(&client->dev, "fail to flash fw (%d)\n", ret);

	return ret;
}

static ssize_t tc300k_fw_ver_ic_show(struct device *dev,
		  struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ver;
	int ret;

	if (data->enabled) {
		data->fdata->fw_update_skip = 0;
		ver = tc300k_get_fw_ver(data);
	}

	ver = data->ic_fw_ver;
	if (ver < 0) {
		dev_err(&client->dev, "%s: fail to read fw ver (%d)\n.",
			__func__, ver);
		ret = sprintf(buf, "%s\n", "error");
		goto out;
	}

	dev_info(&client->dev, "%s: 0x%02x\n", __func__, (u8)ver);
	ret = sprintf(buf, "0x%02x\n", (u8)ver);
out:
	return ret;
}

static ssize_t tc300k_fw_ver_src_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u16 ver;

	if (data->enabled) {
		ret = tc300k_load_fw(data, FW_BUILT_IN);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: fail to load fw (%d)\n.",
				__func__, ret);
			ver = 0;
			goto out;
		}
	}

	ver = data->fw_img->first_fw_ver;

	if (data->enabled) {
		ret = tc300k_unload_fw(data, FW_BUILT_IN);
		if (ret < 0) {
			dev_err(&client->dev,
				"%s: fail to unload fw (%d)\n.",
				__func__, ret);
			ver = 0;
			goto out;
		}
	}

out:
	ret = sprintf(buf, "0x%02x\n", ver);
	dev_info(&client->dev, "%s: 0x%02x\n", __func__, ver);
	return ret;
}

static ssize_t tc300k_fw_update_store(struct device *dev,
		struct device_attribute *devattr,
		const char *buf, size_t count)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 fw_path;

	if (!data->enabled) {
		dev_err(&client->dev,
			"%s: device is disabled (fw_update_skip =% d)\n.",
			__func__, data->fdata->fw_update_skip);
		return -EPERM;
	}

	switch (*buf) {
	case 's':
	case 'S':
		fw_path = FW_BUILT_IN;
		break;
	case 'i':
	case 'I':
		fw_path = FW_IN_SDCARD;
		break;
	default:
		dev_err(&client->dev, "%s: invalid parameter %c\n.", __func__,
			*buf);
		return -EINVAL;
	}

	data->fdata->fw_flash_status = DOWNLOADING;
	data->enabled = false;

	ret = tc300k_flash_fw(data, fw_path, true);
	data->enabled = true;
	if (ret < 0) {
		data->fdata->fw_flash_status = FAIL;
		dev_err(&client->dev,
			"%s: fail to flash fw (%d)\n.", __func__,
			ret);
		return ret;
	}

	data->fdata->fw_flash_status = PASS;

	return count;
}

static ssize_t tc300k_fw_update_status_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;

	switch (data->fdata->fw_flash_status) {
	case DOWNLOADING:
		ret = sprintf(buf, "%s\n", TO_STRING(DOWNLOADING));
		break;
	case FAIL:
		ret = sprintf(buf, "%s\n", TO_STRING(FAIL));
		break;
	case PASS:
		ret = sprintf(buf, "%s\n", TO_STRING(PASS));
		break;
	default:
		dev_err(&client->dev, "%s: invalid status\n", __func__);
		ret = 0;
		goto out;
	}

	dev_info(&client->dev, "%s: %#x\n", __func__,
			data->fdata->fw_flash_status);
			data->fdata->fw_update_skip = 0;

out:
	return ret;
}

static int tc300k_factory_mode_enable(struct i2c_client *client, u8 cmd)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, TC300K_CMD_ADDR, cmd);
	msleep(TC300K_CMD_DELAY);

	return ret;
}

static ssize_t tc300k_factory_mode(struct device *dev,
	 struct device_attribute *attr, const char *buf, size_t count)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int scan_buffer;
	int ret;
	u8 cmd;

	ret = sscanf(buf, "%d", &scan_buffer);
	if (ret != 1) {
		dev_err(&client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(scan_buffer == 0 || scan_buffer == 1)) {
		dev_err(&client->dev, "%s: wrong command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (data->factory_mode == (bool)scan_buffer) {
		dev_info(&client->dev, "%s same command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (scan_buffer == 1) {
		dev_notice(&client->dev, "factory mode\n");
		cmd = TC300K_CMD_FAC_ON;
	} else {
		dev_notice(&client->dev, "normale mode\n");
		cmd = TC300K_CMD_FAC_OFF;
	}

	if ((!data->enabled)) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		data->factory_mode = (bool)scan_buffer;
		return count;
	}

	ret = tc300k_factory_mode_enable(client, cmd);
	if (ret < 0)
		dev_err(&client->dev, "%s fail(%d)\n", __func__, ret);

	data->factory_mode = (bool)scan_buffer;

	return count;
}

static ssize_t tc300k_factory_mode_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", data->factory_mode);
}

static ssize_t recent_key_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	u16 value;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t back_key_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	int value;
	u8 buff[8] = {0, };

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_recent_inner_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	u16 value;
	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_recent_outer_show(struct device *dev,
			 struct device_attribute *attr,
			 char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	u16 value;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_3KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_back_inner_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	int value;
	u8 buff[8] = {0, };

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_back_outer_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	int value;
	u8 buff[8] = {0, };

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_4KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_CH_PCK_H_OFFSET] << 8) |
	buff[TC300K_CH_PCK_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}


static ssize_t recent_key_raw(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int value;

	if (!data->enabled) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t back_key_raw(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int value;

	if ((!data->enabled)) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_recent_raw_inner_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int value;

	if (!data->enabled) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_recent_raw_outer_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int value, ret;
	u8 buff[8] = {0, };

	if (!data->enabled) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_3KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_back_raw_inner_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret, value;
	u8 buff[8] = {0, };

	if ((!data->enabled)) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_back_raw_outer_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int value;

	if ((!data->enabled)) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -1;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_4KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s read fail(%d)\n", __func__, ret);
		return -1;
	}

	value = (buff[TC300K_RAW_H_OFFSET] << 8) |
	buff[TC300K_RAW_L_OFFSET];

	return sprintf(buf, "%d\n", value);
}

static ssize_t tc300k_threshold_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int thr_recent, thr_back;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_recent read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_recent = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_back read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_back = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	dev_info(&client->dev, "%s: %d, %d\n", __func__, thr_recent, thr_back);

	return sprintf(buf, "%d, %d\n", thr_recent, thr_back);
}

static ssize_t tc300k_recent_threshold_inner_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int thr_recent_inner;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_1KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_recent inner read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_recent_inner = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	dev_info(&client->dev, "%s: %d\n", __func__, thr_recent_inner);

	return sprintf(buf, "%d\n", thr_recent_inner);
}

static ssize_t tc300k_recent_threshold_outer_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int thr_recent_outer;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_3KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_recent outer read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_recent_outer = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	dev_info(&client->dev, "%s: %d\n", __func__, thr_recent_outer);

	return sprintf(buf, "%d\n", thr_recent_outer);
}

static ssize_t tc300k_back_threshold_inner_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int thr_back_inner;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_2KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_back inner read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_back_inner = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	dev_info(&client->dev, "%s: %d\n", __func__, thr_back_inner);

	return sprintf(buf, "%d\n", thr_back_inner);
}

static ssize_t tc300k_back_threshold_outer_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 buff[8] = {0, };
	int thr_back_outer;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is disabled\n.", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_i2c_block_data(client, TC300K_4KEY_DATA, 8, buff);
	if (ret != 8) {
		dev_err(&client->dev, "%s: thr_back read fail(%d)\n", __func__, ret);
		return -1;
	}

	thr_back_outer = (buff[TC300K_THRES_H_OFFSET] << 8) |
	buff[TC300K_THRES_L_OFFSET];

	dev_info(&client->dev, "%s: %d\n", __func__, thr_back_outer);

	return sprintf(buf, "%d\n", thr_back_outer);
}

static int tc300k_glove_mode_enable(struct i2c_client *client, u8 cmd)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, TC300K_CMD_ADDR, cmd);
	msleep(TC300K_CMD_DELAY);

	return ret;
}

static ssize_t tc300k_glove_mode(struct device *dev,
	 struct device_attribute *attr, const char *buf, size_t count)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int scan_buffer;
	int ret;
	u8 cmd;

	ret = sscanf(buf, "%d", &scan_buffer);
	if (ret != 1) {
		dev_err(&client->dev, "%s: cmd read err\n", __func__);
		return count;
	}

	if (!(scan_buffer == 0 || scan_buffer == 1)) {
		dev_err(&client->dev, "%s: wrong command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (data->glove_mode == (bool)scan_buffer) {
		dev_info(&client->dev, "%s same command(%d)\n",
			__func__, scan_buffer);
		return count;
	}

	if (scan_buffer == 1) {
		dev_notice(&client->dev, "factory mode\n");
		cmd = TC300K_CMD_GLOVE_ON;
	} else {
		dev_notice(&client->dev, "normale mode\n");
		cmd = TC300K_CMD_GLOVE_OFF;
	}

	if (!data->enabled) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		data->glove_mode = (bool)scan_buffer;
		return count;
	}

	ret = tc300k_glove_mode_enable(client, cmd);
	if (ret < 0)
		dev_err(&client->dev, "%s fail(%d)\n", __func__, ret);

	data->glove_mode = (bool)scan_buffer;

	return count;
}

static ssize_t tc300k_glove_mode_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", data->glove_mode);
}

static ssize_t tc300k_modecheck_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 mode, glove, factory;

	if (!data->enabled) {
		dev_err(&client->dev, "can't excute %s\n", __func__);
		return -EPERM;
	}

	ret = i2c_smbus_read_byte_data(client, TC300K_MODE);
	if (ret < 0) {
		dev_err(&client->dev, "%s: failed to read threshold_h (%d)\n",
			__func__, ret);
		return ret;
	}

	mode = ret;
	glove = ((mode & 0xf0) >> 4);
	factory = mode & 0x0f;

	return sprintf(buf, "glove:%d, factory:%d\n", glove, factory);
}

static DEVICE_ATTR(touchkey_threshold, S_IRUGO, tc300k_threshold_show, NULL);
static DEVICE_ATTR(touchkey_firm_version_panel, S_IRUGO | S_IWUSR | S_IWGRP,
	tc300k_fw_ver_ic_show, NULL);
static DEVICE_ATTR(touchkey_firm_version_phone, S_IRUGO | S_IWUSR | S_IWGRP,
	tc300k_fw_ver_src_show, NULL);
static DEVICE_ATTR(touchkey_firm_update, S_IRUGO | S_IWUSR | S_IWGRP,
	NULL, tc300k_fw_update_store);
static DEVICE_ATTR(touchkey_firm_update_status, S_IRUGO,
	tc300k_fw_update_status_show, NULL);
static DEVICE_ATTR(touchkey_recent, S_IRUGO, recent_key_show, NULL);
static DEVICE_ATTR(touchkey_back, S_IRUGO, back_key_show, NULL);
static DEVICE_ATTR(touchkey_raw_recent, S_IRUGO, recent_key_raw, NULL);
static DEVICE_ATTR(touchkey_raw_back, S_IRUGO, back_key_raw, NULL);
static DEVICE_ATTR(glove_mode, S_IRUGO | S_IWUSR | S_IWGRP,
	tc300k_glove_mode_show, tc300k_glove_mode);
static DEVICE_ATTR(touchkey_factory_mode, S_IRUGO | S_IWUSR | S_IWGRP,
	tc300k_factory_mode_show, tc300k_factory_mode);
static DEVICE_ATTR(modecheck, S_IRUGO, tc300k_modecheck_show, NULL);
static DEVICE_ATTR(touchkey_recent_threshold_inner, S_IRUGO, tc300k_recent_threshold_inner_show, NULL);
static DEVICE_ATTR(touchkey_recent_threshold_outer, S_IRUGO, tc300k_recent_threshold_outer_show, NULL);
static DEVICE_ATTR(touchkey_back_threshold_inner, S_IRUGO, tc300k_back_threshold_inner_show, NULL);
static DEVICE_ATTR(touchkey_back_threshold_outer, S_IRUGO, tc300k_back_threshold_outer_show, NULL);
static DEVICE_ATTR(touchkey_recent_raw_inner, S_IRUGO, tc300k_recent_raw_inner_show, NULL);
static DEVICE_ATTR(touchkey_recent_raw_outer, S_IRUGO, tc300k_recent_raw_outer_show, NULL);
static DEVICE_ATTR(touchkey_back_raw_inner, S_IRUGO, tc300k_back_raw_inner_show, NULL);
static DEVICE_ATTR(touchkey_back_raw_outer, S_IRUGO, tc300k_back_raw_outer_show, NULL);
static DEVICE_ATTR(touchkey_recent_inner, S_IRUGO, tc300k_recent_inner_show, NULL);
static DEVICE_ATTR(touchkey_recent_outer, S_IRUGO, tc300k_recent_outer_show, NULL);
static DEVICE_ATTR(touchkey_back_inner, S_IRUGO, tc300k_back_inner_show, NULL);
static DEVICE_ATTR(touchkey_back_outer, S_IRUGO, tc300k_back_outer_show, NULL);

static struct attribute *touchkey_attributes[] = {
	&dev_attr_touchkey_threshold.attr,
	&dev_attr_touchkey_firm_version_panel.attr,
	&dev_attr_touchkey_firm_version_phone.attr,
	&dev_attr_touchkey_firm_update.attr,
	&dev_attr_touchkey_firm_update_status.attr,
	&dev_attr_touchkey_recent.attr,
	&dev_attr_touchkey_back.attr,
	&dev_attr_touchkey_raw_recent.attr,
	&dev_attr_touchkey_raw_back.attr,
	&dev_attr_touchkey_factory_mode.attr,
	&dev_attr_glove_mode.attr,
	&dev_attr_modecheck.attr,
	&dev_attr_touchkey_recent_threshold_inner.attr,
	&dev_attr_touchkey_recent_threshold_outer.attr,
	&dev_attr_touchkey_back_threshold_inner.attr,
	&dev_attr_touchkey_back_threshold_outer.attr,
	&dev_attr_touchkey_recent_raw_inner.attr,
	&dev_attr_touchkey_recent_raw_outer.attr,
	&dev_attr_touchkey_back_raw_inner.attr,
	&dev_attr_touchkey_back_raw_outer.attr,
	&dev_attr_touchkey_recent_inner.attr,
	&dev_attr_touchkey_recent_outer.attr,
	&dev_attr_touchkey_back_inner.attr,
	&dev_attr_touchkey_back_outer.attr,
	NULL,
};

static struct attribute_group touchkey_attr_group = {
	.attrs = touchkey_attributes,
};

#ifdef CONFIG_PM
static void tc300k_input_close(struct input_dev *dev)
{
	struct tc300k_data *data = input_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int i;

	mutex_lock(&data->lock);

	if (unlikely(wake_lock_active(&data->fw_wake_lock))) {
		dev_info(&data->client->dev,
			"%s, now fw updating. suspend "
			 "control is ignored.\n", __func__);
		goto out;
	}

	if (!data->enabled) {
		dev_info(&client->dev,
			"%s, already disabled.\n", __func__);
		goto out;
	}

	disable_irq(client->irq);
	data->enabled = false;

	/* report not released key */
	for (i = 0; i < data->num_key; i++)
		input_report_key(data->input_dev, data->keycodes[i], 0);

	input_sync(data->input_dev);

	tc300k_led_power(data,false);
	tc300k_power(data,0);
	data->led_on = false;
out:
	mutex_unlock(&data->lock);
	dev_info(&client->dev, "%s\n", __func__);

	return;
}

static int tc300k_input_open(struct input_dev *dev)
{
	struct tc300k_data *data = input_get_drvdata(dev);
	struct i2c_client *client = data->client;
	int ret;
	u8 cmd;

	mutex_lock(&data->lock);

	if (unlikely(wake_lock_active(&data->fw_wake_lock))) {
		dev_info(&client->dev, "%s, now fw updating. resume "
			 "control is ignored.\n", __func__);
		goto out;
	}

	if (data->enabled) {
		dev_info(&client->dev, "%s, already enabled.\n", __func__);
		goto out;
	}

	if (data->pinctrl) {
		ret = tkey_pinctrl_configure(data, false);
		if (ret)
			dev_err(&client->dev, "%s: cannot set pinctrl state\n", __func__);
	}

	tc300k_led_power(data,true);
	tc300k_power(data,1);
	msleep(5);
	if (data->pinctrl) {
		ret = tkey_pinctrl_configure(data, true);
		if (ret)
			pr_err("%s: cannot set pinctrl state\n", __func__);
	}

	msleep(200 - 5);
	enable_irq(client->irq);
	data->enabled = true;
	if (data->led_on == true) {
		data->led_on = false;
		dev_notice(&client->dev, "led on(resume)\n");
		cmd = TC300K_CMD_LED_ON;
		ret = i2c_smbus_write_byte_data(client, TC300K_CMD_ADDR, cmd);
		if (ret < 0)
			dev_err(&client->dev, "%s led on fail(%d)\n", __func__, ret);
		else
			msleep(TC300K_CMD_DELAY);
	}

	if (data->glove_mode) {
		ret = tc300k_glove_mode_enable(client, TC300K_CMD_GLOVE_ON);
		if (ret < 0)
			dev_err(&client->dev, "%s glovemode fail(%d)\n", __func__, ret);
	}

	if (data->factory_mode) {
		ret = tc300k_factory_mode_enable(client, TC300K_CMD_FAC_ON);
		if (ret < 0)
			dev_err(&client->dev, "%s factorymode fail(%d)\n", __func__, ret);
	}
out:
	mutex_unlock(&data->lock);
	data->release_cnt = 0;
	dev_info(&client->dev, "%s\n", __func__);
	return 0;
}
#endif

static irqreturn_t tc300k_interrupt(int irq, void *dev_id)
{
	struct tc300k_data *data = dev_id;
	struct i2c_client *client = data->client;
	u32 key_val;
	int i;

	if (!data->enabled) {
		dev_err(&client->dev, "%s: device is not enabled.\n", __func__);
		goto out;
	}

	key_val = i2c_smbus_read_byte_data(client, TC300K_KEYCODE);
	if (!key_val) {
		dev_err(&client->dev, "failed to read key data (%d)\n", key_val);
		goto out;
	}

	for (i = 0 ; i < data->num_key*2; i++) {
		if ((key_val & data->tsk_ev_val[i].tsk_bitmap)) {
			input_report_key(data->input_dev,
				data->tsk_ev_val[i].tsk_keycode,
				data->tsk_ev_val[i].tsk_status);

			if (!data->tsk_ev_val[i].tsk_status)
				data->release_cnt++;
		}
	}
	input_sync(data->input_dev);

out:
	return IRQ_HANDLED;
}

static int tc300k_init_interface(struct tc300k_data *data)
{
	struct i2c_client *client = data->client;
	int ret;

	data->fdata->dummy_dev = device_create(sec_class, NULL,
		MKDEV(SEC_DEV_TOUCHKEY_MAJOR, SEC_DEV_TOUCHKEY_MINOR),
		data, TC300K_DEVICE);
	if (IS_ERR(data->fdata->dummy_dev)) {
	dev_err(&client->dev, "Failed to create fac tsp temp dev\n");
	ret = -ENODEV;
	data->fdata->dummy_dev = NULL;
	goto err_create_sec_class_dev;
	}

	ret = sysfs_create_group(&data->fdata->dummy_dev->kobj,
		 &touchkey_attr_group);
	if (ret) {
	dev_err(&client->dev, "%s: failed to create fac_attr_group "
		"(%d)\n", __func__, ret);
	ret = (ret > 0) ? -ret : ret;
	goto err_create_fac_attr_group;
	}

	return 0;

	sysfs_remove_group(&data->fdata->dummy_dev->kobj,
		&touchkey_attr_group);
err_create_fac_attr_group:
	device_destroy(sec_class, data->fdata->dummy_dev->devt);
err_create_sec_class_dev:
	return ret;
}

#ifdef CONFIG_SLEEP_MONITOR
#define	PRETTY_MAX	14
#define	STATE_BIT	24
#define	CNT_MASK	0xffff
#define	STATE_MASK	0xff

static int tc300k_get_sleep_monitor_cb(void* priv, unsigned int *raw_val, int check_level, int caller_type);

static struct sleep_monitor_ops  tc300k_sleep_monitor_ops = {
	 .read_cb_func =  tc300k_get_sleep_monitor_cb,
};

static int tc300k_get_sleep_monitor_cb(void* priv, unsigned int *raw_val, int check_level, int caller_type)
{
	struct tc300k_data *data = priv;
	struct i2c_client *client = data->client;
	int state = DEVICE_UNKNOWN;
	int pwr_mode;
	int pretty;

	if (check_level == SLEEP_MONITOR_CHECK_SOFT) {
		if (data->enabled)
			state = DEVICE_ON_ACTIVE1;
		else
			state = DEVICE_POWER_OFF;
	} else if (check_level == SLEEP_MONITOR_CHECK_HARD) {
		if (data->enabled)
			state = DEVICE_ON_ACTIVE1;
		else
			state = DEVICE_POWER_OFF;
	}

	*raw_val = ((state & STATE_MASK) << STATE_BIT) |\
			(data->release_cnt & CNT_MASK);

	if (data->release_cnt > PRETTY_MAX)
		pretty = PRETTY_MAX;
	else
		pretty = data->release_cnt;

	dev_dbg(&client->dev, "%s: raw_val[0x%08x], check_level[%d], release_cnt[%d], state[%d], pretty[%d]\n",
		__func__, *raw_val, check_level, data->release_cnt, state, pretty);

	return pretty;
}
#endif

#ifdef CONFIG_OF
static int tc300k_parse_dt_keycodes(struct device *dev, char *name,
				struct tc300k_platform_data *pdata)
{
	struct property *prop;
	struct device_node *np = dev->of_node;
	int rc = 0, i;

	prop = of_find_property(np, name, NULL);
	if (!prop)
		return -EINVAL;
	if (!prop->value)
		return -ENODATA;

	pdata->num_key = prop->length / sizeof(u32);

	rc = of_property_read_u32_array(np, name, pdata->keycodes, pdata->num_key);
	if (rc && (rc != -EINVAL)) {
		dev_err(dev, "%s: Unable to read %s\n", __func__, name);
		return rc;
	}

	for (i = 0; i < pdata->num_key; i++)
		dev_info(dev, "%s: keycode[%d] = [%d]\n",
			__func__, i, pdata->keycodes[i]);

	return 0;
}


static int tc300k_parse_dt(struct device *dev,
		struct tc300k_platform_data *pdata)
{
	struct device_node *np = dev->of_node;
	int rc;

//	pdata->num_key =ARRAY_SIZE(tc300k_keycodes);
//	pdata->keycodes = tc300k_keycodes;

	rc = tc300k_parse_dt_keycodes(dev, "coreriver,keycodes", pdata);
	if (rc) {
		dev_err(dev, "%s: Unable to read keycodes rc = %d\n", __func__, rc);
		return rc;
	}

	pdata->gpio_en = of_get_named_gpio_flags(np, "coreriver,vcc_en-gpio", 0, &pdata->vcc_gpio_flags);
	pdata->gpio_scl = of_get_named_gpio_flags(np, "coreriver,scl-gpio", 0, &pdata->scl_gpio_flags);
	pdata->gpio_sda = of_get_named_gpio_flags(np, "coreriver,sda-gpio", 0, &pdata->sda_gpio_flags);
	pdata->gpio_int = of_get_named_gpio_flags(np, "coreriver,irq-gpio", 0, &pdata->irq_gpio_flags);
	pdata->firmup = of_property_read_bool(np, "coreriver,firm-up");
	pdata->gpio_2p8_en = of_get_named_gpio_flags(np, "coreriver,vcc_en-gpio2p8", 0, &pdata->vcc_gpio2p8_flags);

	rc = of_property_read_string(np, "coreriver,fw-name", &pdata->fw_name);
	if (rc < 0) {
		dev_err(dev, "%s: Unable to read fw-name. rc = %d\n", __func__, rc);
	}

	rc = of_property_read_string(np, "coreriver,vcc_en_ldo_name", &pdata->vcc_en_ldo_name);
	if (rc < 0) {
		dev_err(dev, "%s: Unable to read vcc_en_ldo_name. rc = %d\n", __func__, rc);
	}

	rc = of_property_read_string(np, "coreriver,vdd_led_ldo_name", &pdata->vdd_led_ldo_name);
	if (rc < 0) {
		dev_err(dev, "%s: Unable to read vdd_led_ldo_name. rc = %d\n", __func__, rc);
	}

//	dev_info(dev, "%s: fw-name: [%s]\n", __func__, pdata->fw_name);
	dev_info(dev, "%s: gpio_en = [%d], tkey_scl= [%d], tkey_sda= [%d], tkey_int= [%d], firmup= [%d]\n",
		__func__, pdata->gpio_en, pdata->gpio_scl, pdata->gpio_sda, pdata->gpio_int, pdata->firmup);

	return 0;
}
#else
static int tc300k_parse_dt(struct device *dev,
		struct tc300k_platform_data *pdata)
{
	return -ENODEV;
}
#endif

static int tc300k_probe(struct i2c_client *client,
		 const struct i2c_device_id *id)
{
	struct tc300k_platform_data *pdata;
	struct i2c_adapter *adapter = to_i2c_adapter(client->dev.parent);
	struct tc300k_data *data;
	struct input_dev *input_dev;
	int ret, i, err;

	dev_info(&client->dev, "%s\n", __func__);

	if (!i2c_check_functionality(adapter, I2C_FUNC_I2C))
		return -EIO;

	if (client->dev.of_node) {
		pdata = devm_kzalloc(&client->dev,
				sizeof(struct tc300k_platform_data),
				GFP_KERNEL);
		if (!pdata) {
			dev_err(&client->dev, "Failed to allocate memory\n");
			return -ENOMEM;
		}

		err = tc300k_parse_dt(&client->dev, pdata);
		if (err) {
			dev_err(&client->dev, "Failed to parse dt data.\n");
			return err;
		}
	} else
		pdata = client->dev.platform_data;

	data = kzalloc(sizeof(struct tc300k_data), GFP_KERNEL);
	if (!data) {
		dev_err(&client->dev, "failed to alloc memory\n");
		ret = -ENOMEM;
		goto err_data_alloc;
	}

	data->fdata = kzalloc(sizeof(struct fdata_struct), GFP_KERNEL);
	if (!data->fdata) {
		dev_err(&client->dev, "failed to alloc memory for fdata\n");
		ret = -ENOMEM;
		goto err_data_alloc_fdata;
	}

	input_dev = input_allocate_device();
	if (!input_dev) {
		dev_err(&client->dev, "failed to allocate input device\n");
		ret = -ENOMEM;
		goto err_input_devalloc;
	}

	data->client = client;
	data->pdata = pdata;
	data->input_dev = input_dev;
	data->num_key = pdata->num_key;
	data->keycodes = pdata->keycodes;
	data->suspend_type = pdata->suspend_type;
	data->scl = pdata->gpio_scl;
	data->sda = pdata->gpio_sda;

	tc300k_gpio_request(data);

#if 0
	/* Get pinctrl if target uses pinctrl */
	data->pinctrl = devm_pinctrl_get(&client->dev);
	if (IS_ERR(data->pinctrl)) {
		if (PTR_ERR(data->pinctrl) == -EPROBE_DEFER)
			dev_err(&client->dev,
				"%s: pinctrl is EPROBE_DEFER\n", __func__);
		dev_err(&client->dev,
			"%s: Target does not use pinctrl\n", __func__);
		data->pinctrl = NULL;
	}
	if (data->pinctrl) {
		ret = tkey_pinctrl_configure(data, false);
		if (ret)
			dev_err(&client->dev,
				"%s: cannot set pinctrl state\n", __func__);
	}
#endif
	tc300k_led_power(data,1);
	tc300k_power(data,1);
	msleep(5);

	if (data->pinctrl) {
		ret = tkey_pinctrl_configure(data, true);
		if (ret)
			dev_err(&client->dev,
				"%s: cannot set pinctrl state\n", __func__);
	}
	msleep(TC300K_POWERON_DELAY - 5);

	mutex_init(&data->lock);
	wake_lock_init(&data->fw_wake_lock, WAKE_LOCK_SUSPEND, "tc300k_fw_wake_lock");

	client->irq=gpio_to_irq(pdata->gpio_int);

	snprintf(data->phys, sizeof(data->phys), "%s/input0", dev_name(&client->dev));
	input_dev->name = TC300K_DEVICE;
	input_dev->phys = data->phys;
	input_dev->id.bustype = BUS_I2C;
	input_dev->dev.parent = &client->dev;
	input_dev->keycode = data->keycodes;
	input_dev->keycodesize = sizeof(data->keycodes[0]);
	input_dev->keycodemax = data->num_key;
	data->tsk_ev_val = tsk_ev;
#ifdef CONFIG_PM_SLEEP
	input_dev->open = tc300k_input_open;
	input_dev->close = tc300k_input_close;
#endif

	set_bit(EV_SYN, input_dev->evbit);
	set_bit(EV_ABS, input_dev->evbit);
	set_bit(EV_LED, input_dev->evbit);
	set_bit(LED_MISC, input_dev->ledbit);
	for (i = 0; i < data->num_key; i++) {
		input_set_capability(input_dev, EV_KEY, data->keycodes[i]);
		set_bit(data->keycodes[i], input_dev->keybit);
	}

	i2c_set_clientdata(client, data);
	input_set_drvdata(input_dev, data);
	ret = input_register_device(data->input_dev);
	if (ret) {
		dev_err(&client->dev, "fail to register input_dev (%d).\n",
			ret);
		goto err_register_input_dev;
	}

	ret = tc300k_init_interface(data);
	if (ret < 0) {
		dev_err(&client->dev, "failed to init interface (%d)\n", ret);
		goto err_init_interface;
	}

	/* Add symbolic link */
	ret = sysfs_create_link(&data->fdata->dummy_dev->kobj, &input_dev->dev.kobj, "input");
	if (ret < 0) {
		dev_err(&client->dev,
			"%s: Failed to create input symbolic link\n",
			__func__);
	}
	dev_set_drvdata(data->fdata->dummy_dev, data);
	dev_set_drvdata(&client->dev, data);

	if (client->irq) {
		ret = request_threaded_irq(client->irq, NULL, tc300k_interrupt,
				IRQF_TRIGGER_FALLING | IRQF_ONESHOT , TC300K_DEVICE, data);
		if (ret) {
			dev_err(&client->dev, "fail to request irq (%d).\n",
			client->irq);
			goto err_request_irq;
		}
	}

	ret = tc300k_load_firmware(data);
	if (ret < 0) {
		dev_err(&client->dev, "fail to load touchkey firmware. (%d).\n",
			ret);
		goto err_initialize;
	}

#ifdef CONFIG_SLEEP_MONITOR
	sleep_monitor_register_ops(data, &tc300k_sleep_monitor_ops,
			SLEEP_MONITOR_TOUCHKEY);
#endif

	data->enabled = true;
	dev_info(&client->dev, "successfully probed.\n");

	return 0;

err_initialize:
	free_irq(client->irq, data);
err_request_irq:
	sysfs_remove_group(&data->fdata->dummy_dev->kobj,
		&touchkey_attr_group);
	device_destroy(sec_class, data->fdata->dummy_dev->devt);
err_init_interface:
	input_unregister_device(input_dev);
	input_dev = NULL;
err_register_input_dev:
	wake_lock_destroy(&data->fw_wake_lock);
	if (input_dev)
	input_free_device(input_dev);
err_input_devalloc:
	kfree(data->fdata);
err_data_alloc_fdata:
	kfree(data);
err_data_alloc:
	return ret;
}

static int tc300k_remove(struct i2c_client *client)
{
	struct tc300k_data *data = i2c_get_clientdata(client);

#ifdef CONFIG_SLEEP_MONITOR
	sleep_monitor_unregister_ops(SLEEP_MONITOR_TOUCHKEY);
#endif
	free_irq(client->irq, data);
	gpio_free(data->pdata->gpio_int);
	input_unregister_device(data->input_dev);
	input_free_device(data->input_dev);
	kfree(data->fdata);
	kfree(data);

	return 0;
}

static const struct i2c_device_id tc300k_id[] = {
	{ TC300K_DEVICE, 0 },
	{ }
};

#ifdef CONFIG_OF
static struct of_device_id coreriver_match_table[] = {
	{ .compatible = "coreriver,coreriver-tkey",},
	{ },
};
#else
#define coreriver_match_table	NULL
#endif

#ifndef CONFIG_HAS_EARLYSUSPEND
static int tc300k_suspend(struct device *dev)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct input_dev *input_dev = data->input_dev;

	tc300k_input_close(input_dev);

	return 0;
}

static int tc300k_resume(struct device *dev)
{
	struct tc300k_data *data = dev_get_drvdata(dev);
	struct input_dev *input_dev = data->input_dev;

	return tc300k_input_open(input_dev);
}
#endif

MODULE_DEVICE_TABLE(i2c, tc300k_id);

#ifndef CONFIG_HAS_EARLYSUSPEND
const struct dev_pm_ops tc300k_pm_ops = {
	.suspend = tc300k_suspend,
	.resume = tc300k_resume,
};
#endif

static struct i2c_driver tc300k_driver = {
	.probe	= tc300k_probe,
	.remove	= tc300k_remove,
	.driver = {
	.name	= TC300K_DEVICE,
#ifdef CONFIG_OF
	.of_match_table = coreriver_match_table,
#endif
#ifndef CONFIG_HAS_EARLYSUSPEND
	.pm			= &tc300k_pm_ops,
#endif
	},
	.id_table	= tc300k_id,
};

static int __init tc300k_init(void)
{
	int ret = 0;

	ret = i2c_add_driver(&tc300k_driver);
	if (ret) {
		printk(KERN_ERR "coreriver touch keypad"
			" registration failed. ret= %d\n",
			ret);
	}

	return ret;
}

static void __exit tc300k_exit(void)
{
	i2c_del_driver(&tc300k_driver);
}

module_init(tc300k_init);
module_exit(tc300k_exit);

MODULE_AUTHOR("Samsung Electronics");
MODULE_DESCRIPTION("Touchkey driver for Coreriver TC300K");
MODULE_LICENSE("GPL");
