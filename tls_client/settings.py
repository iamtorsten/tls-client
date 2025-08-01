from typing_extensions import Literal, TypeAlias

# https://github.com/bogdanfinn/tls-client/blob/master/profiles/profiles.go
ClientIdentifiers: TypeAlias = Literal[
    # Chrome
    "chrome_103",
    "chrome_104",
    "chrome_105",
    "chrome_106",
    "chrome_107",
    "chrome_108",
    "chrome_109",
    "chrome_110",
    "chrome_111",
    "chrome_112",
    "chrome_116_PSK",
    "chrome_116_PSK_PQ",
    "chrome_117",
    "chrome_120",
    "chrome_124",
    "chrome_131_PSK",
	"chrome_133",
	"chrome_133_PSK",
    # Safari
    "safari_15_6_1",
    "safari_16_0",
    # iOS (Safari)
    "safari_ipad_15_6",
    "safari_ios_15_5",
    "safari_ios_15_6",
    "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0",
    # iPadOS (Safari)
    "safari_ios_15_6",
    # FireFox
    "firefox_102",
    "firefox_104",
    "firefox_105",
    "firefox_106",
    "firefox_108",
    "firefox_110",
    "firefox_117",
    "firefox_120",
    "firefox_123",
    "firefox_132",
    "firefox_133",
    "firefox_135",
    # Opera
    "opera_89",
    "opera_90",
    "opera_91",
    # OkHttp4
    "okhttp4_android_7",
    "okhttp4_android_8",
    "okhttp4_android_9",
    "okhttp4_android_10",
    "okhttp4_android_11",
    "okhttp4_android_12",
    "okhttp4_android_13",
    # Custom
    "zalando_ios_mobile",
    "zalando_android_mobile",
    "nike_ios_mobile",
    "nike_android_mobile",
    "cloudscraper",
    "mms_ios",
    "mms_ios_1",
    "mms_ios_2",
    "mms_ios_3",
    "mesh_ios",
    "mesh_ios_1",
    "mesh_ios_2",
    "mesh_android",
    "mesh_android_1",
    "mesh_android_2",
    "confirmed_ios",
    "confirmed_android",
    "confirmed_android_7",
    "confirmed_android_8",
    "confirmed_android_9",
    "confirmed_android_10",
    "confirmed_android_11",
    "confirmed_android_12",
    "confirmed_android_13",
]
