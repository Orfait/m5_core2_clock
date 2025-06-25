/*
 * SPDX-FileCopyrightText: 2010-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: CC0-1.0
 */

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include <inttypes.h>
#include <stdio.h>

#include <esp_http_server.h>
#include <esp_ota_ops.h>
#include <mqtt_client.h>
#include <nvs.h>
#include <nvs_flash.h>

#include <M5Unified.h>
#include <esp_netif_sntp.h>
#include <led_strip.h>
#include <time.h>

#define LED_RMT
#define STRINGIZE(x) #x
#define CONCAT(x, y) x##y
#define HOSTNAME        "reveil-lewis"
#define MQTT_SUBTOPIC   "/data"
//STRINGIZE(CONCAT(HOSTNAME, MQTT_SUBTOPIC))
#define MQTT_TOPIC      STRINGIZE(CONCAT(HOSTNAME, MQTT_SUBTOPIC))

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// Utility
static char *getJsonValuePtr(const char *json, const char *key);

// HTTPD
static httpd_handle_t httpdServer = NULL;
extern const char html_index[] asm("_binary_index_html_start");
extern const char css_pico_min[] asm("_binary_pico_min_css_start");

// WIFI
static void wifiEventHandler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void setWifiCredentials(const char *ssid, const char *pass);
static void startWifi(void);
static bool enableAP_auto = false;
static esp_netif_t *esp_netif_sta;
static esp_netif_t *esp_netif_ap;
static char currentIPStr[16] = {0};
static char currentMACStr[13] = {0};

// Event group for connectivity
static EventGroupHandle_t connectivity_event_group;
static const int EVENT_CONNECTIVITY_AP_READY = BIT0;
static const int EVENT_CONNECTIVITY_AP_CONNECTED = BIT1;
static const int EVENT_CONNECTIVITY_PROV_DONE = BIT2;
static const int EVENT_CONNECTIVITY_GOT_IP = BIT3;
static const int EVENT_CONNECTIVITY_MQTT_CONNECTED = BIT4;

// MQTT
static void mqttEventHandler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data);
static void mqttSetBroker(char *address);
static void logErrorIfNonZero(const char *message, int error_code);
static esp_mqtt_client_handle_t mqttClient = NULL;
static char mqttTopicIn[] = HOSTNAME "/command";
static char mqttTopicOut[] = HOSTNAME "/status";

// APP
const char name[] = {HOSTNAME};
typedef union {
    uint16_t val16;
    struct __attribute__((packed)) {
        uint8_t min;
        uint8_t hour;
    };
} mytime_t;
typedef enum : uint8_t {
    unknown,
    automatic,
    day,
    night,
    nap
} clockMode;
static struct
{
    clockMode mode;
    uint8_t school;
    mytime_t night_start, night_end, night_end_school, nap_start, nap_end;
    bool wasChanged;
    clockMode currentMode = unknown;
    mytime_t currentTime;
    clockMode nextMode = unknown;
    bool analogDisplay = true;
    uint8_t currentSeconds;
} clockData;
static void parseJsonData(const char *json);
static size_t makeJson(char *buffer, size_t len);
static void readConfig(void);
static void writeConfig(void);
static void displayClock(void);
static led_strip_handle_t leds;
static void configureLeds(void);
static void setLedColor(clockMode mode);
static void init(void);
static void time_sync_notification_cb(struct timeval *tv);

extern "C" void app_main();

char *getJsonValuePtr(const char *json, const char *key) {
    char *pKeyStr;
    char quotedKey[200];

    snprintf(quotedKey, sizeof(quotedKey), "\"%s\"", key);

    pKeyStr = strstr(json, quotedKey);
    if (pKeyStr != nullptr) {
        pKeyStr = strstr(pKeyStr, ":") + 1;
    }

    return pKeyStr;
}

void wifiEventHandler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    static const char *TAG = "WIFI";
    static int reconnect_count = 0;
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            xEventGroupClearBits(connectivity_event_group, EVENT_CONNECTIVITY_GOT_IP);
            ESP_LOGI(TAG, "Disconnected. Connecting to the AP again...");
            reconnect_count++;
            if (reconnect_count == 5) {
                enableAP_auto = true;
                startWifi();
            } else {
                esp_wifi_connect();
            }
            break;
        case WIFI_EVENT_AP_START:
            xEventGroupSetBits(connectivity_event_group, EVENT_CONNECTIVITY_AP_READY);
            ESP_LOGI(TAG, "SoftAP started");
            break;
        case WIFI_EVENT_AP_STOP:
            xEventGroupClearBits(connectivity_event_group, EVENT_CONNECTIVITY_AP_READY);
            ESP_LOGI(TAG, "SoftAP stopped");
            break;
        case WIFI_EVENT_AP_STACONNECTED:
            xEventGroupSetBits(connectivity_event_group, EVENT_CONNECTIVITY_AP_CONNECTED);
            ESP_LOGI(TAG, "SoftAP transport: Connected");
            break;
        case WIFI_EVENT_AP_STADISCONNECTED:
            xEventGroupClearBits(connectivity_event_group, EVENT_CONNECTIVITY_AP_CONNECTED);
            ESP_LOGI(TAG, "SoftAP transport: Disconnected");
            break;
        default:
            break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        snprintf(currentIPStr, sizeof(currentIPStr), IPSTR, IP2STR(&event->ip_info.ip));
        currentIPStr[15] = '\0';
        ESP_LOGI(TAG, "Connected with IP Address: %s", currentIPStr);
        /* Signal main application to continue execution */
        xEventGroupSetBits(connectivity_event_group, EVENT_CONNECTIVITY_GOT_IP);
        enableAP_auto = false;
        if (mqttClient != NULL) {
            esp_mqtt_client_reconnect(mqttClient);
        }
    }
}

void setWifiCredentials(const char *ssid, const char *pass) {
    wifi_config_t wifi_sta_config;
    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA, &wifi_sta_config));

    if ((ssid != NULL) && (pass != NULL)) {
        if (strnlen(ssid, sizeof(wifi_sta_config.sta.ssid)) > 0) {
            if ((strncmp((char *)wifi_sta_config.sta.ssid, ssid, sizeof(wifi_sta_config.sta.ssid)) == 0) && (strncmp((char *)wifi_sta_config.sta.password, pass, sizeof(wifi_sta_config.sta.password)) == 0)) {
                // WiFi config unchanged
                ESP_LOGI("WIFI", "SSID and PASSWORD are unchanged, returning.");
                return;
            } else {
                strncpy((char *)wifi_sta_config.sta.ssid, ssid, sizeof(wifi_sta_config.sta.ssid));
                strncpy((char *)wifi_sta_config.sta.password, pass, sizeof(wifi_sta_config.sta.password));
                ESP_LOGI("WIFI", "Changed SSID: %s and PASS: %s", wifi_sta_config.sta.ssid, wifi_sta_config.sta.password);
            }
        }
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config));
    enableAP_auto = false;
    startWifi();
}

void startWifi(void) {
    bool hasSSID = false;
    wifi_config_t wifi_ap_config;
    wifi_config_t wifi_sta_config;

    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_AP, &wifi_ap_config));
    ESP_ERROR_CHECK(esp_wifi_get_config(WIFI_IF_STA, &wifi_sta_config));

    wifi_ap_config.ap.channel = 11;
    wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;
    wifi_ap_config.ap.max_connection = 4;
    wifi_ap_config.ap.pmf_cfg.required = false;

    uint8_t eth_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
    wifi_ap_config.ap.ssid_len = snprintf((char *)wifi_ap_config.ap.ssid, sizeof(wifi_ap_config.ap.ssid), "PROV_%02X%02X%02X", eth_mac[3], eth_mac[4], eth_mac[5]);

    if (strlen((const char *)wifi_sta_config.sta.ssid)) {
        hasSSID = true;
    } else {
        enableAP_auto = true;
    }

    esp_wifi_stop();
    esp_netif_destroy_default_wifi(esp_netif_sta);
    esp_netif_sta = NULL;
    esp_netif_destroy_default_wifi(esp_netif_ap);
    esp_netif_ap = NULL;

    if (enableAP_auto) {
        esp_netif_ap = esp_netif_create_default_wifi_ap();
        esp_netif_sta = esp_netif_create_default_wifi_sta();
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    } else {
        esp_netif_sta = esp_netif_create_default_wifi_sta();
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    }

    ESP_ERROR_CHECK(esp_netif_set_hostname(esp_netif_sta, name));

    if (enableAP_auto) {
        ESP_LOGI("WIFI", "AP mode selected (SSID:%s)", wifi_ap_config.ap.ssid);
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_ap_config));
    }

    if (hasSSID) {
        ESP_LOGI("WIFI", "STA mode selected (SSID:\"%s\"  PASS:\"%s\")", wifi_sta_config.sta.ssid, wifi_sta_config.sta.password);
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_sta_config));
        xEventGroupSetBits(connectivity_event_group, EVENT_CONNECTIVITY_PROV_DONE);
    }

    ESP_ERROR_CHECK(esp_wifi_start());
}

void mqttEventHandler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    static const char *TAG = "MQTT_EVT";
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%" PRIi32 "", base, event_id);
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    switch ((esp_mqtt_event_id_t)event_id) {
    case MQTT_EVENT_CONNECTED:
        xEventGroupSetBits(connectivity_event_group, EVENT_CONNECTIVITY_MQTT_CONNECTED);
        ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
        msg_id = esp_mqtt_client_subscribe(client, mqttTopicIn, 0);
        ESP_LOGI(TAG, "sent subscribe successful, msg_id=%d, topic=%s", msg_id, mqttTopicIn);
        break;
    case MQTT_EVENT_DISCONNECTED:
        xEventGroupClearBits(connectivity_event_group, EVENT_CONNECTIVITY_MQTT_CONNECTED);
        ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
        break;
    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_UNSUBSCRIBED:
        ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_PUBLISHED:
        ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
        break;
    case MQTT_EVENT_DATA:
        ESP_LOGI(TAG, "MQTT_EVENT_DATA");
        // printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
        // printf("DATA=%.*s\r\n", event->data_len, event->data);
        {
            char * buffer = (char *)malloc(event->data_len + 1);
            if (buffer != nullptr) {
                snprintf(buffer, event->data_len + 1, "%.*s", event->data_len, event->data);
                parseJsonData(buffer);
                free(buffer);
            }
        }
        break;
    case MQTT_EVENT_ERROR:
        ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
        if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
            logErrorIfNonZero("reported from esp-tls", event->error_handle->esp_tls_last_esp_err);
            logErrorIfNonZero("reported from tls stack", event->error_handle->esp_tls_stack_err);
            logErrorIfNonZero("captured as transport's socket errno", event->error_handle->esp_transport_sock_errno);
            ESP_LOGI(TAG, "Last errno string (%s)", strerror(event->error_handle->esp_transport_sock_errno));
        }
        break;
    default:
        ESP_LOGI(TAG, "Other event id:%d", event->event_id);
        break;
    }
}

void mqttStart(void) {
    static const char *TAG = "MQTT_START";
    char address[64] = {0};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    esp_mqtt_client_config_t mqttConfig = {
        .broker = {
            .address = {
                .uri = address}},
        .session = {.protocol_ver = MQTT_PROTOCOL_V_3_1_1}};
#pragma GCC diagnostic pop

    if (mqttClient != NULL) {
        return;
    }

    nvs_handle nvs;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs));
    size_t mqttAddressLength;
    esp_err_t ret = nvs_get_str(nvs, "mqtt", NULL, &mqttAddressLength);
    if (ret == ESP_OK) {
        char *buf = (char *)malloc(mqttAddressLength);
        nvs_get_str(nvs, "mqtt", buf, &mqttAddressLength);
        strncpy(address, buf, sizeof(address));
        free(buf);
    }
    nvs_close(nvs);

    ESP_LOGI(TAG, "Broker: %s", mqttConfig.broker.address.uri);
    mqttClient = esp_mqtt_client_init(&mqttConfig);
    esp_mqtt_client_register_event(mqttClient, MQTT_EVENT_ANY, mqttEventHandler, NULL);
    esp_mqtt_client_start(mqttClient);
}

void mqttSetBroker(char *address) {
    static const char *TAG = "MQTT_SET_BROKER";
    size_t length = strnlen(address, 256);
    if (length) {
        nvs_handle nvs;
        ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs));

        size_t mqttAddressLength = length + strlen("mqtt://") + 1;
        char *newAddress = (char *)malloc(mqttAddressLength);
        snprintf(newAddress, mqttAddressLength, "mqtt://%s", address);
        ESP_LOGI(TAG, "New Broker address: %s", newAddress);
        nvs_set_str(nvs, "mqtt", newAddress);
        nvs_commit(nvs);
        nvs_close(nvs);

        if (mqttClient != NULL) {
            esp_mqtt_client_disconnect(mqttClient);
            esp_mqtt_client_stop(mqttClient);
            esp_mqtt_client_set_uri(mqttClient, newAddress);
            esp_mqtt_client_start(mqttClient);
        }

        free(newAddress);
    }
}

void logErrorIfNonZero(const char *message, int error_code) {
    static const char *TAG = "MQTT_ERROR";
    if (error_code != 0) {
        ESP_LOGE(TAG, "Last error %s: 0x%x", message, error_code);
    }
}

static esp_err_t httpd_get_req_pico_min_css(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/css");
    int response = httpd_resp_send(req, css_pico_min, HTTPD_RESP_USE_STRLEN);
    return response;
}

static esp_err_t httpd_get_req_root(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", "index.html");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t httpd_get_req_index_html(httpd_req_t *req) {
    int response = httpd_resp_send(req, html_index, HTTPD_RESP_USE_STRLEN);
    return response;
}

static esp_err_t httpd_post_req_index_html(httpd_req_t *req) {
    char *buf = (char *)malloc(req->content_len + 1);
    size_t offset = 0;
    while (offset < req->content_len) {
        /* Read data received in the request */
        int ret = httpd_req_recv(req, buf + offset, req->content_len - offset);
        if (ret <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                httpd_resp_send_408(req);
            }
            free(buf);
            return ESP_FAIL;
        }
        offset += ret;
        ESP_LOGI("WEBS", "root_post_handler recv length %d", ret);
    }
    buf[offset] = '\0';

    parseJsonData(buf);

    free(buf);

    buf = (char *)malloc(256);
    size_t len = makeJson(buf, 256);
    ESP_LOGI("WEBS", "send json data, len: %d", len);
    httpd_resp_set_type(req, "application/json");
    int response = httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);
    free(buf);
    return response;
}

static esp_err_t httpd_post_req_update(httpd_req_t *req) {
    char buf[1000];
    esp_ota_handle_t ota_handle;
    int remaining = req->content_len;

    const esp_partition_t *ota_partition = esp_ota_get_next_update_partition(NULL);
    ESP_ERROR_CHECK(esp_ota_begin(ota_partition, OTA_SIZE_UNKNOWN, &ota_handle));

    while (remaining > 0) {
        int recv_len = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)));

        // Timeout Error: Just retry
        if (recv_len == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;

            // Serious Error: Abort OTA
        } else if (recv_len <= 0) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Protocol Error");
            return ESP_FAIL;
        }

        // Successful Upload: Flash firmware chunk
        if (esp_ota_write(ota_handle, (const void *)buf, recv_len) != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Flash Error");
            return ESP_FAIL;
        }

        remaining -= recv_len;
    }

    // Validate and switch to new OTA image and reboot
    if (esp_ota_end(ota_handle) != ESP_OK || esp_ota_set_boot_partition(ota_partition) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Validation / Activation Error");
        return ESP_FAIL;
    }

    httpd_resp_sendstr(req, "Firmware update complete, rebooting now!\n");

    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();

    return ESP_OK;
}

void parseJsonData(const char *json) {
    static const char *TAG = "parseJsonData";
    char *ptr_start;

    ESP_LOGI(TAG, "%s", json);

    // Try to get mqtt broker
    ptr_start = getJsonValuePtr(json, "mqtt");
    if (ptr_start != nullptr) {
        char mqtt[64] = {0};
        if (sscanf(ptr_start, "\"%64[^\" ]\"", mqtt) == 1) {
            ESP_LOGI(TAG, "mqtt: %s\n", mqtt);
            mqttSetBroker(mqtt);
        }
    }

    // Try to get time
    ptr_start = getJsonValuePtr(json, "time");
    if (ptr_start != nullptr) {
        int hour, minute;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &minute) == 2) {
            ESP_LOGI(TAG, "time: %02ih%02im\n", hour, minute);
            // TODO: set time
        }
    }

    // Try to get WiFi info
    ptr_start = getJsonValuePtr(json, "ssid");
    if (ptr_start != nullptr) {
        char ssid[32] = {0};
        char pass[64] = {0};
        if (sscanf(ptr_start, "\"%32[^\" ]\"", ssid) == 1) {
            ESP_LOGI(TAG, "ssid: %s\n", ssid);
            ptr_start = getJsonValuePtr(json, "pass");
            if (ptr_start != nullptr) {
                if (sscanf(ptr_start, "\"%64[^\" ]\"", pass) == 1) {
                    ESP_LOGI(TAG, "pass: %s\n", pass);
                    setWifiCredentials(ssid, pass);
                }
            }
        }
    }

    // Try to get mode
    ptr_start = getJsonValuePtr(json, "mode");
    if (ptr_start != nullptr) {
        char *ptr_mode;
        clockMode mode = automatic;

        ptr_mode = strstr(ptr_start, "\"nap\"");
        mode = ((ptr_mode - ptr_start) < 2 && (ptr_mode != NULL)) ? nap : mode;

        ptr_mode = strstr(ptr_start, "\"night\"");
        mode = ((ptr_mode - ptr_start) < 2 && (ptr_mode != NULL)) ? night : mode;

        ptr_mode = strstr(ptr_start, "\"day\"");
        mode = ((ptr_mode - ptr_start) < 2 && (ptr_mode != NULL)) ? day : mode;

        if (clockData.mode != mode) {
            clockData.mode = mode;
            clockData.wasChanged = true;
        }
    }

    // Try to get school
    ptr_start = getJsonValuePtr(json, "school");
    if (ptr_start != nullptr) {
        char *ptr_school = strstr(ptr_start, "true");
        bool school = ((ptr_school - ptr_start) < 2 && (ptr_school != NULL)) ? 1 : 0;
        if (clockData.school != school) {
            clockData.school = school;
            clockData.wasChanged = true;
        }
    }

    // Try to get night_start
    ptr_start = getJsonValuePtr(json, "night_start");
    if (ptr_start != nullptr) {
        int hour, min;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &min) == 2) {
            mytime_t time = {
                .min = (uint8_t)min,
                .hour = (uint8_t)hour};
            if (clockData.night_start.val16 != time.val16) {
                clockData.night_start.val16 = time.val16;
                clockData.wasChanged = true;
            }
        }
    }

    // Try to get night_end
    ptr_start = getJsonValuePtr(json, "night_end");
    if (ptr_start != nullptr) {
        int hour, min;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &min) == 2) {
            mytime_t time = {
                .min = (uint8_t)min,
                .hour = (uint8_t)hour};
            if (clockData.night_end.val16 != time.val16) {
                clockData.night_end.val16 = time.val16;
                clockData.wasChanged = true;
            }
        }
    }

    // Try to get night_end_school
    ptr_start = getJsonValuePtr(json, "night_end_school");
    if (ptr_start != nullptr) {
        int hour, min;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &min) == 2) {
            mytime_t time = {
                .min = (uint8_t)min,
                .hour = (uint8_t)hour};
            if (clockData.night_end_school.val16 != time.val16) {
                clockData.night_end_school.val16 = time.val16;
                clockData.wasChanged = true;
            }
        }
    }

    // Try to get nap_start
    ptr_start = getJsonValuePtr(json, "nap_start");
    if (ptr_start != nullptr) {
        int hour, min;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &min) == 2) {
            mytime_t time = {
                .min = (uint8_t)min,
                .hour = (uint8_t)hour};
            if (clockData.nap_start.val16 != time.val16) {
                clockData.nap_start.val16 = time.val16;
                clockData.wasChanged = true;
            }
        }
    }

    // Try to get nap_end
    ptr_start = getJsonValuePtr(json, "nap_end");
    if (ptr_start != nullptr) {
        int hour, min;
        if (sscanf(ptr_start, "\"%02d:%02d\"", &hour, &min) == 2) {
            mytime_t time = {
                .min = (uint8_t)min,
                .hour = (uint8_t)hour};
            if (clockData.nap_end.val16 != time.val16) {
                clockData.nap_end.val16 = time.val16;
                clockData.wasChanged = true;
            }
        }
    }
}

size_t makeJson(char *buffer, size_t len) {
    size_t offset = 0;
    offset += snprintf(&buffer[offset], len - offset, "{\"mode\":");
    switch (clockData.mode) {
    case unknown:
        offset += snprintf(&buffer[offset], len - offset, "\"unknown\"");
        break;
    case automatic:
        offset += snprintf(&buffer[offset], len - offset, "\"auto\"");
        break;
    case day:
        offset += snprintf(&buffer[offset], len - offset, "\"day\"");
        break;
    case night:
        offset += snprintf(&buffer[offset], len - offset, "\"night\"");
        break;
    case nap:
        offset += snprintf(&buffer[offset], len - offset, "\"nap\"");
        break;
    default:
        break;
    }

    if (clockData.school == 0) {
        offset += snprintf(&buffer[offset], len - offset, ",\"school\":false");
    } else {
        offset += snprintf(&buffer[offset], len - offset, ",\"school\":true");
    }

    offset += snprintf(&buffer[offset], len - offset, ",\"night_start\":\"%02d:%02d\"", clockData.night_start.hour, clockData.night_start.min);

    offset += snprintf(&buffer[offset], len - offset, ",\"night_end\":\"%02d:%02d\"", clockData.night_end.hour, clockData.night_end.min);

    offset += snprintf(&buffer[offset], len - offset, ",\"night_end_school\":\"%02d:%02d\"", clockData.night_end_school.hour, clockData.night_end_school.min);

    offset += snprintf(&buffer[offset], len - offset, ",\"nap_start\":\"%02d:%02d\"", clockData.nap_start.hour, clockData.nap_start.min);

    offset += snprintf(&buffer[offset], len - offset, ",\"nap_end\":\"%02d:%02d\"", clockData.nap_end.hour, clockData.nap_end.min);

    offset += snprintf(&buffer[offset], len - offset, "}");

    ESP_LOGI("makeJson", "%s", buffer);

    return offset + 1;
}

void readConfig(void) {
    nvs_handle nvs;

    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs));

    if (nvs_get_u8(nvs, "mode", (uint8_t *)&clockData.mode) != ESP_OK) {
        clockData.mode = automatic;
        clockData.wasChanged = true;
    }

    if (nvs_get_u8(nvs, "school", &clockData.school) != ESP_OK) {
        clockData.school = 1;
        clockData.wasChanged = true;
    }

    if (nvs_get_u16(nvs, "night_start", &clockData.night_start.val16) != ESP_OK) {
        clockData.night_start.hour = 20;
        clockData.night_start.min = 0;
        clockData.wasChanged = true;
    }
    if (nvs_get_u16(nvs, "night_end", &clockData.night_end.val16) != ESP_OK) {
        clockData.night_end.hour = 9;
        clockData.night_end.min = 0;
        clockData.wasChanged = true;
    }
    if (nvs_get_u16(nvs, "night_end_scho", &clockData.night_end_school.val16) != ESP_OK) {
        clockData.night_end_school.hour = 7;
        clockData.night_end_school.min = 10;
        clockData.wasChanged = true;
    }
    if (nvs_get_u16(nvs, "nap_start", &clockData.nap_start.val16) != ESP_OK) {
        clockData.nap_start.hour = 13;
        clockData.nap_start.min = 0;
        clockData.wasChanged = true;
    }
    if (nvs_get_u16(nvs, "nap_end", &clockData.nap_end.val16) != ESP_OK) {
        clockData.nap_end.hour = 16;
        clockData.nap_end.min = 30;
        clockData.wasChanged = true;
    }

    nvs_close(nvs);
}

void writeConfig(void) {
    if (clockData.wasChanged == false) {
        return;
    }

    nvs_handle nvs;

    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs));

    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u8(nvs, "mode", (uint8_t)clockData.mode));

    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u8(nvs, "school", clockData.school));

    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u16(nvs, "night_start", clockData.night_start.val16));
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u16(nvs, "night_end", clockData.night_end.val16));
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u16(nvs, "night_end_scho", clockData.night_end_school.val16));
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u16(nvs, "nap_start", clockData.nap_start.val16));
    ESP_ERROR_CHECK_WITHOUT_ABORT(nvs_set_u16(nvs, "nap_end", clockData.nap_end.val16));

    nvs_close(nvs);
    clockData.wasChanged = false;
}

void displayClock(void) {
    static bool init = true;
    static M5Canvas canvas(&M5.Display);
    static int32_t w = M5.Display.width();
    static int32_t h = M5.Display.height();
    static float displayRatio = (float)w / 140.0f;
    static uint32_t uiColor = M5.Display.color888(100, 100, 100);
    static uint32_t uiColorDarkRed = M5.Display.color888(100, 0, 0);
    static uint32_t uiColorDarkBlue = M5.Display.color888(0, 0, 100);
    static uint32_t uiColorDarkGreen = M5.Display.color888(0, 100, 0);

    clockMode _mode = unknown;
    uint8_t hours, minutes;
    

    if (init) {
        canvas.createSprite(w, h);
        init = false;
    }
    canvas.fillSprite(TFT_BLACK);

    if (clockData.mode == automatic) {
        _mode = clockData.currentMode;
    } else {
        _mode = clockData.mode;
    }

    hours = clockData.currentTime.hour % 24;
    minutes = clockData.currentTime.min % 60;

    if (clockData.analogDisplay) {
        uint32_t radius = ((w < h ? w : h) / 2) - 9;
        uint32_t x_center = w/2;
        uint32_t y_center = h/2;
        int32_t x0, y0, x1, y1;

        uint32_t radiusMinutes = radius - 13;
        uint32_t radiusHours = (radiusMinutes * 2) / 3;

        // Ring of dots
        for (uint8_t i = 1; i <= 60; i++) {    
            x0 = x_center + (radiusMinutes - 3) * cosf(((float)(i - 15) * 2.0f * M_PI) / 60.0f);
            y0 = y_center + (radiusMinutes - 3) * sinf(((float)(i - 15) * 2.0f * M_PI) / 60.0f);      
            x1 = x_center + radiusMinutes * cosf(((float)(i - 15) * 2.0f * M_PI) / 60.0f);
            y1 = y_center + radiusMinutes * sinf(((float)(i - 15) * 2.0f * M_PI) / 60.0f);
            
            if (i % 5 == 0) {
                canvas.drawWideLine(x0, y0, x1, y1, 2, uiColor);
            } else {
                canvas.fillCircle(x1, y1, 1, uiColor);
            }
        }

        //
        x1 = x_center + radiusMinutes * cosf(((float)(minutes - 15) * 2.0f * M_PI) / 60.0f);
        y1 = y_center + radiusMinutes * sinf(((float)(minutes - 15) * 2.0f * M_PI) / 60.0f);
        canvas.drawWideLine(x_center, y_center, x1, y1, 3, uiColorDarkBlue);

        //
        float hoursWithMinutes = (float)hours + (float)minutes / 60.0f;
        x1 = x_center + radiusHours * cosf(((hoursWithMinutes - 3.0) * 2.0f * M_PI) / 12.0f);
        y1 = y_center + radiusHours * sinf(((hoursWithMinutes - 3.0) * 2.0f * M_PI) / 12.0f);
        canvas.drawWideLine(x_center, y_center, x1, y1, 4, uiColorDarkGreen);

        // Numbers
        canvas.setFont(&fonts::FreeMonoBold12pt7b);
        canvas.setTextDatum(middle_center);
        canvas.setTextSize(1);
        canvas.setTextColor(uiColor);
        for (uint8_t i = 1; i <= 12; i++) {
            char numberString[3];
            
            x1 = x_center + radius * cosf(((float)(i - 3) * 2.0f * M_PI) / 12.0f);
            y1 = y_center + radius * sinf(((float)(i - 3) * 2.0f * M_PI) / 12.0f) + 1;
            //canvas.fillCircle(x1, y1, 9, uiColor);
            snprintf(numberString, sizeof(numberString), "%d", i);
            canvas.drawString(numberString, x1, y1);
        }

        //
        x1 = x_center + radiusMinutes * cosf(((float)(clockData.currentSeconds - 15) * 2.0f * M_PI) / 60.0f);
        y1 = y_center + radiusMinutes * sinf(((float)(clockData.currentSeconds - 15) * 2.0f * M_PI) / 60.0f);
        canvas.drawWideLine(x_center, y_center, x1, y1, 1, uiColorDarkRed);

        //
        canvas.fillCircle(x_center, y_center, 7, uiColor);

        if (clockData.school) {
            canvas.setTextSize(1);
            canvas.setFont(&fonts::FreeMonoBold9pt7b);
            canvas.setTextColor(uiColor);
            canvas.setTextDatum(bottom_right);
            canvas.drawString("ECOLE", w, h);
        }
    } else {
        char timeString[6];

        canvas.setFont(&fonts::Font7);
        canvas.setTextDatum(top_center);
        canvas.setTextSize(displayRatio);
        canvas.setTextColor(uiColor);
        snprintf(timeString, sizeof(timeString), "%02d:%02d", hours, minutes);
        canvas.drawString(timeString, w / 2, 0);

        if (clockData.school) {
            canvas.setTextSize(displayRatio / 2);
            canvas.setFont(&fonts::Font4);
            canvas.setTextColor(uiColor);
            canvas.setTextDatum(bottom_center);
            canvas.drawString("ECOLE", w / 2, h);
        }
    }
    canvas.pushSprite(0, 0);

    if (_mode == day) {
        M5.Display.setBrightness(100);
    } else if (_mode == nap) {
        M5.Display.setBrightness(50);
    } else if (_mode == night) {
        M5.Display.setBrightness(1);
    }

    setLedColor(_mode);
}

void configureLeds(void) {
    static const char *TAG = "LED_INIT";
#ifdef LED_RMT
    // LED strip general initialization, according to your led board design
    led_strip_config_t strip_config = {
        .strip_gpio_num = 33,                                        // The GPIO that connected to the LED strip's data line
        .max_leds = 2,                                               // The number of LEDs in the strip,
        .led_model = LED_MODEL_WS2812,                               // LED strip model : LED_MODEL_SK6812 / LED_MODEL_WS2812
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB, // The color order of the strip: GRB
        .flags = {
            .invert_out = false, // don't invert the output signal
        }};

    // LED strip backend configuration: RMT
    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT, // different clock source can lead to different power consumption
        .resolution_hz = 10000000,      // RMT counter clock frequency
        .mem_block_symbols = 64,        // the memory size of each RMT channel, in words (4 bytes)
        .flags = {
            .with_dma = false, // DMA feature is available on chips like ESP32-S3/P4
        }};

    // LED Strip object handle
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &leds));
#else
    // LED strip general initialization, according to your led board design
    led_strip_config_t strip_config = {
        .strip_gpio_num = 33,          // The GPIO that connected to the LED strip's data line
        .max_leds = 2,                 // The number of LEDs in the strip,
        .led_model = LED_MODEL_WS2812, // LED strip model
        // set the color order of the strip: GRB
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags = {
            .invert_out = false, // don't invert the output signal
        }};

    // LED strip backend configuration: SPI
    led_strip_spi_config_t spi_config = {
        .clk_src = SPI_CLK_SRC_DEFAULT, // different clock source can lead to different power consumption
        .spi_bus = SPI2_HOST,           // SPI bus ID
        .flags = {
            .with_dma = true, // Using DMA can improve performance and help drive more LEDs
        }};

    // LED Strip object handle
    ESP_ERROR_CHECK(led_strip_new_spi_device(&strip_config, &spi_config, &leds));
#endif

    ESP_LOGI(TAG, "Created LED strip object with RMT backend");
    ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_clear(leds));
    return;
}

void setLedColor(clockMode mode) {
    static clockMode _mode = unknown;

    if (_mode != mode) {
        _mode = mode;
        switch (_mode) {
        case day:
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 0, 0x00, 0x00, 0x00));
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 1, 0x77, 0x55, 0x55));
            break;
        case night:
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 0, 0x04, 0x03, 0x03));
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 1, 0x00, 0x00, 0x00));
            break;
        case nap:
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 0, 0x33, 0x22, 0x22));
            ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_set_pixel(leds, 1, 0x00, 0x00, 0x00));
            break;
        default:
            return;
        }
        ESP_ERROR_CHECK_WITHOUT_ABORT(led_strip_refresh(leds));
    }
}

void init(void) {
    static const char *TAG = "INIT";
    uint8_t eth_mac[6];
    httpd_config_t httpdConfig = HTTPD_DEFAULT_CONFIG();
    httpd_uri_t httpd_uri_getcss = {
        .uri = "/pico.min.css",
        .method = HTTP_GET,
        .handler = httpd_get_req_pico_min_css,
        .user_ctx = NULL};
    httpd_uri_t httpd_uri_getroot = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = httpd_get_req_root,
        .user_ctx = NULL};
    httpd_uri_t httpd_uri_getindex = {
        .uri = "/index.html",
        .method = HTTP_GET,
        .handler = httpd_get_req_index_html,
        .user_ctx = NULL};
    httpd_uri_t httpd_uri_postindex = {
        .uri = "/index.html",
        .method = HTTP_POST,
        .handler = httpd_post_req_index_html,
        .user_ctx = NULL};
    httpd_uri_t httpd_uri_postupdate = {
        .uri = "/update",
        .method = HTTP_POST,
        .handler = httpd_post_req_update,
        .user_ctx = NULL};

    /* Initialize TCP/IP */
    ESP_ERROR_CHECK(esp_netif_init());

    /* Initialize the event loop */
    ESP_LOGI(TAG, "Creating default event loop");
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    connectivity_event_group = xEventGroupCreate();

    /* Register our event handler for Wi-Fi, IP and Provisioning related events */
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifiEventHandler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifiEventHandler, NULL));

    /*Initialize WiFi */
    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    esp_wifi_get_mac(WIFI_IF_STA, eth_mac);
    snprintf(currentMACStr, sizeof(currentMACStr), "%02X%02X%02X%02X%02X%02X", eth_mac[0], eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]);
    currentMACStr[12] = '\0';

    ESP_ERROR_CHECK(httpd_start(&httpdServer, &httpdConfig));
    ESP_ERROR_CHECK(httpd_register_uri_handler(httpdServer, &httpd_uri_getcss));
    ESP_ERROR_CHECK(httpd_register_uri_handler(httpdServer, &httpd_uri_getroot));
    ESP_ERROR_CHECK(httpd_register_uri_handler(httpdServer, &httpd_uri_getindex));
    ESP_ERROR_CHECK(httpd_register_uri_handler(httpdServer, &httpd_uri_postindex));
    ESP_ERROR_CHECK(httpd_register_uri_handler(httpdServer, &httpd_uri_postupdate));

    startWifi();
    mqttStart();

    setenv("TZ", "CET-1CEST-2,M3.5.0/02:00:00,M10.5.0/03:00:00", 1);
    tzset();
    esp_sntp_config_t esp_netif_sntp_config = ESP_NETIF_SNTP_DEFAULT_CONFIG("pool.ntp.org");
    //esp_netif_sntp_config.server_from_dhcp = true;                 // accept the NTP offers from DHCP server
    //esp_netif_sntp_config.renew_servers_after_new_IP = true;       // let esp-netif update the configured SNTP server(s) after receiving the DHCP lease
    //esp_netif_sntp_config.index_of_first_server = 1;               // updates from server num 1, leaving server 0 (from DHCP) intact
    //esp_netif_sntp_config.ip_event_to_renew = IP_EVENT_STA_GOT_IP; // IP event on which you refresh your configuration
    esp_netif_sntp_config.sync_cb = time_sync_notification_cb;
    esp_netif_sntp_init(&esp_netif_sntp_config);
}

void time_sync_notification_cb(struct timeval *tv) {
    struct tm timeinfo;

    gmtime_r(&tv->tv_sec, &timeinfo);
    M5.Rtc.setDateTime(&timeinfo);

    ESP_LOGI("SNTP", "New Time : %02d:%02d:%02d", timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

void app_main(void) {
    TickType_t xLastWakeTime;
    const TickType_t xFrequency1Sec = pdMS_TO_TICKS(1000);
    char * buffer;

    /* Initialize NVS partition */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        /* NVS partition was truncated
         * and needs to be erased */
        ESP_ERROR_CHECK(nvs_flash_erase());

        /* Retry nvs_flash_init */
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    readConfig();

    M5.begin();
    M5.Display.setBrightness(0);
    configureLeds();
    init();

    xLastWakeTime = xTaskGetTickCount();
    while (1) {
        writeConfig();
        M5.update();

        time_t timestamp = time(NULL);
        struct tm *pTime = localtime(&timestamp);
        // if ((clockData.currentTime.hour != pTime->tm_hour) || (clockData.currentTime.min != pTime->tm_min)) {
        clockData.currentTime.hour = pTime->tm_hour;
        clockData.currentTime.min = pTime->tm_min;
        clockData.currentSeconds = pTime->tm_sec;

        mytime_t wakeup;
        if ((pTime->tm_wday != 0) && (pTime->tm_wday != 6) && (clockData.school != 0)) {
            wakeup.val16 = clockData.night_end_school.val16;
        } else {
            wakeup.val16 = clockData.night_end.val16;
        }

        if (clockData.currentTime.val16 < wakeup.val16) {
            clockData.nextMode = night;
        } else if (clockData.currentTime.val16 < clockData.nap_start.val16) {
            clockData.nextMode = day;
        } else if (clockData.currentTime.val16 < clockData.nap_end.val16) {
            clockData.nextMode = nap;
        } else if (clockData.currentTime.val16 < clockData.night_start.val16) {
            clockData.nextMode = day;
        } else {
            clockData.nextMode = night;
        }

        if (clockData.currentMode == unknown) {
            clockData.currentMode = clockData.nextMode;
        }

        if (clockData.currentMode != clockData.nextMode) {
            if (clockData.mode == clockData.nextMode) {
                clockData.mode = automatic;
            }
            clockData.currentMode = clockData.nextMode;
        }

        displayClock();
        //}

        // printf("\r\ncurrentMode: %d\r\nnextMode: %d\r\nmode: %d", clockData.currentMode, clockData.nextMode, clockData.mode);

        buffer = (char *)malloc(256);
        size_t len = makeJson(buffer, 256);
        esp_mqtt_client_publish(mqttClient, mqttTopicOut, buffer, len - 1, 0, 0);
        free(buffer);

        vTaskDelayUntil(&xLastWakeTime, xFrequency1Sec);
    }
}
