idf_component_register(SRCS "main.cpp"
                    PRIV_REQUIRES esp_wifi spi_flash nvs_flash mqtt esp_http_server app_update
                    INCLUDE_DIRS ""
                    EMBED_TXTFILES index.html pico.min.css)
