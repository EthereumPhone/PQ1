/*
* Copyright 2024 NXP
* SPDX-License-Identifier: Apache-2.0
*/

#include <stdint.h>
#include <string.h>

#if RSA_KEY_TYPE

/* Root CA Certficate */
const char rootca_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDqzCCApOgAwIBAgIULSwu13zfrlcQykPW/QaOO4251ZUwDQYJKoZIhvcNAQEL\r\n"
    "BQAwZTELMAkGA1UEBhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIG\r\n"
    "A1UECgwLTlhQLURlbW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJ\r\n"
    "bG9jYWxob3N0MB4XDTIwMDkyODA3NDkyM1oXDTIzMDYyNTA3NDkyM1owZTELMAkG\r\n"
    "A1UEBhMCQUIxCzAJBgNVBAgMAlhZMQswCQYDVQQHDAJMSDEUMBIGA1UECgwLTlhQ\r\n"
    "LURlbW8tQ0ExEjAQBgNVBAsMCURlbW8tVW5pdDESMBAGA1UEAwwJbG9jYWxob3N0\r\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGEl/ssrMtUNHvyLvSoR\r\n"
    "KSzFo9dqFX1Hwsr7Go4S2K88w+EXI/bJ+i9FyWE9qA0AYgG0LrLV+DjJNW6CP6rh\r\n"
    "YCZZswFm/NZV0vpoiIawwY7EJbvSa1cjwK+sgEtMS633Z66qRzTNneVzfE+hBSlH\r\n"
    "yLfII6QiU4in48w1j5Y0QUJV+1mLhJh4vYwFaD/vqwrLl0yTZrmSZkWfL+s47XNR\r\n"
    "u49xfpRdWmeZgyAyX3zJkhIt/kBfP9YrJW5REgqMIWQCbg+dUaMixjRbyjkxQk5H\r\n"
    "2QwKxBjTTJdfZZ0WK4tSGnal/T4BmS8hdVbSO6+D/DstWRPeo7Ixu87UtjsATRUz\r\n"
    "7wIDAQABo1MwUTAdBgNVHQ4EFgQUHnpsphn+phJi29POIOW+9upcG7kwHwYDVR0j\r\n"
    "BBgwFoAUHnpsphn+phJi29POIOW+9upcG7kwDwYDVR0TAQH/BAUwAwEB/zANBgkq\r\n"
    "hkiG9w0BAQsFAAOCAQEAOz6DrhBuTPiacFdaGSw/ePZZ/YbU8jeyRJ8R3TiEzX6d\r\n"
    "e5fJkfHlC0p2b34ZQnpEOLzwHmqaDJQLxzsOc5N6qHDgYh+DR2ZreVVxgpKlcfED\r\n"
    "kHgVMKPbQiUnoYldIq5k0D+11AMYq1ApmmQH+5iBlAk6oSRgcErDbbZBbLvkUZMs\r\n"
    "4i24r3RVsDdZyiSMMdII9S9MopwKLKrUThcnTKYx9AA2zHEXvUprRUUnDD1Xe5t1\r\n"
    "2trRhnlXEuq+Rk0GxsKLgVBpJjmUxzaOqhB4h9JyyLKLJktV8nS68SmOZsQ6sqYG\r\n"
    "w0CLUv3hGXOlICbOAIE1NDdnuQ2wp9Is2M/HK0zRJQ==\r\n"
    "-----END CERTIFICATE-----\r\n";

int rootca_file_len = sizeof(rootca_file);

#if WITH_SE05X
/* Read keys from SE */
const char devkey_file[]  = "";
int devkey_file_len       = sizeof(devkey_file);
const char devcert_file[] = "";
int devcert_file_len      = sizeof(devcert_file);

#else

const char devkey_file[] =
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIIEpQIBAAKCAQEA7b/CxRfStz06kNJNrq6viLb6UxSh2F734C8j/0ORxnRNHk7W\r\n"
    "0SrWrmBTyue76HDfqe+SfAR8u75rPuj1VYAoz/Hz7K8M6P50babtaOgtMwf/dhOr\r\n"
    "+3xvL9fTrdCRX/fFCyAFJoyK9FtRSWlL5zXyw+R4hOXGNyol2efLm7ZCctWsRTPo\r\n"
    "iqE5PSS1Ux6daXDM50zqteZRB5Y+p06fM6dosB1JmWWD5coCC3z4SRrMi9+N4Znn\r\n"
    "lTM+qA72wfqsQIWVXJWK5kWdgAXMlu+SeGMcGtPFOZfO5WtSpBeMIIazTmoG+IWy\r\n"
    "IvfVbxXKtn/g1QhAu3/FYAuzPauNeQIeKQyFUwIDAQABAoIBAQCtxVQ5tIDqN5F/\r\n"
    "2oa2360jEwKCCPmGaVtpe2snHx8EW2smdN9kQJhrGbMFAj2A1kdUMOvzQ2Bb5QEE\r\n"
    "GUd/981ct+7els+r2JgGsVSjMdgfjX/1sMkqZjfqUyi/yUsIRtO5nuzE0UKa+ce/\r\n"
    "DXxSAUdwUKSaFku7dE34KAjUxfFpdkTwmijsq8/P/IYMfF6I6GGXWmWs7fVHoOjq\r\n"
    "beBIyLwn6GN3VSwJexwQOda7cYCK3U/OtwuSm2LRfpnJjMoldQwk2hZeCeM99NdN\r\n"
    "8WXeAvTZFcP0FHrsaTKS9rbLue3rK7jqhvkH2FxZD8hO1+NwT8banKbI98Z5sjG2\r\n"
    "hyyOam0xAoGBAPdcIdChtUoQRkZ+FDuyGIGky9L0jv9r4M+bXGC9pnzarN7bj3un\r\n"
    "Iqq+vXOow1pNLMc4ixP50Bz0onUTG0m+MIkAKaLPIYJ3Igi+HHRZOOi1dn55wL04\r\n"
    "27WC/W/Qf0QLTWLAyl2E/mJBrVhKHHC/ZJTG/XEzPnxkHrAG3TvCVxBLAoGBAPYN\r\n"
    "sI5bk1PejmVK3uUCbv0hzrxGLq88+/4N8jgDGu1b2iRxgSrNnqir0cOQuAIXdfr5\r\n"
    "5F/0/E8ulm/Xw7f8RJx2IGqZUUeqkRTC/T4uKtqAyHDxovINVgBv8L3AqE/0UmvY\r\n"
    "FvpYtv3nZs3k4DofGmEw2thivpsTSX9KXdwwGwoZAoGBAKhTLLuhXxGAU6Iip7gb\r\n"
    "sGuAbicmvqx3h6se6NT4GXQ7Boo81L3rdT7Fv3wWKqGnhMIo6xNz2rfpjSeoEdiz\r\n"
    "sKl5z9t3ojD6ytEyNYDDOmO5IGJejdb1+yTgd4AAXKo8GrQJx2uuVcEdOk2rWQEs\r\n"
    "bNCFPPAsU+gn5W4ZrbC9xatTAoGBAKo8mH42D73ESqL8ZTDvORk77cxHhn9J41NI\r\n"
    "FOD6DQRSO6BhQ6v4raAnmK8FDrqrvr4RbReS6YpjQkRJdSlziYjzFcSLJTg/Y7eI\r\n"
    "nSwLRyz8UzIJjOKJpYoR6O9wP0NqWCgzTtqQzLLpCjDD/PtZj6fU5GU4FIY4lu5R\r\n"
    "5pS0V9DpAoGAIfrxblxRszEv8c+YXMkTwjB+HaD3UxH+ZgJoE2n0r7pnoKj7dEL0\r\n"
    "7ZBOrfQQCQ3DDn8CaZm2iynshlg9SPZZ/Go2ua5AmMOI0YXGTWhcBnOg3yUEUjp9\r\n"
    "uz7Lm7NDcvmlenG/V9WZWI4a7C8UBvDak5f3UWUREd/MNj9vowXeZ0M=\r\n"
    "-----END RSA PRIVATE KEY-----\r\n";
int devkey_file_len = sizeof(devkey_file);

const char devcert_file[] =
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDUTCCAjkCFFiwiMy0GD97OKdGwAtfalsFylN9MA0GCSqGSIb3DQEBCwUAMGUx\r\n"
    "CzAJBgNVBAYTAkFCMQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoM\r\n"
    "C05YUC1EZW1vLUNBMRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2Fs\r\n"
    "aG9zdDAeFw0yMDA5MjgwNzQ5MjRaFw0yMzA2MjUwNzQ5MjRaMGUxCzAJBgNVBAYT\r\n"
    "AkFCMQswCQYDVQQIDAJYWTELMAkGA1UEBwwCTEgxFDASBgNVBAoMC05YUC1EZW1v\r\n"
    "LUNBMRIwEAYDVQQLDAlEZW1vLVVuaXQxEjAQBgNVBAMMCWxvY2FsaG9zdDCCASIw\r\n"
    "DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO2/wsUX0rc9OpDSTa6ur4i2+lMU\r\n"
    "odhe9+AvI/9DkcZ0TR5O1tEq1q5gU8rnu+hw36nvknwEfLu+az7o9VWAKM/x8+yv\r\n"
    "DOj+dG2m7WjoLTMH/3YTq/t8by/X063QkV/3xQsgBSaMivRbUUlpS+c18sPkeITl\r\n"
    "xjcqJdnny5u2QnLVrEUz6IqhOT0ktVMenWlwzOdM6rXmUQeWPqdOnzOnaLAdSZll\r\n"
    "g+XKAgt8+EkazIvfjeGZ55UzPqgO9sH6rECFlVyViuZFnYAFzJbvknhjHBrTxTmX\r\n"
    "zuVrUqQXjCCGs05qBviFsiL31W8VyrZ/4NUIQLt/xWALsz2rjXkCHikMhVMCAwEA\r\n"
    "ATANBgkqhkiG9w0BAQsFAAOCAQEAiMRAhaLv6ffpHve6yCiHlmhhV7FLsxG6iCJ1\r\n"
    "pAinc04r8BH12kKNleX8RCENC1CUqi0G3KZikIxadNLjH/OAocD/ZdjVsHIe0Bmj\r\n"
    "/mRNkbAAky0KTlmrsirGmDNgxUZeWmww8T7efHTd1WpgNwBDB8tLGwzrzC0mOu0W\r\n"
    "tC5yCe4w55pUBoiBxSM3t1SMW4AY42viCOab4ItOwu+TcFX080rL1w8yYb99SoB9\r\n"
    "M5nQ6J4xukzQVn6/3Pk9bmAP74MD72EMdJFrqVu89QDEVfTea3/GZdEpDeqToJgr\r\n"
    "CKwOsECbJBDgF54LJf5avuaO4P+saSt3UbUu0IJIP3+jzjfRBw==\r\n"
    "-----END CERTIFICATE-----\r\n";

int devcert_file_len = sizeof(devcert_file);

#endif //#if WITH_SE05X
#endif //#if ECC_KEY_TYPE