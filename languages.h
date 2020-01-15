/*
   p0f - ISO 639-1 languages
   -------------------------

   Copyright (C) 2012 by Michal Zalewski <lcamtuf@coredump.cx>

   Distributed under the terms and conditions of GNU LGPL.

 */

#ifndef HAVE_LANGUAGES_H_
#define HAVE_LANGUAGES_H_

#define MAX_LANG 3

#define LANG_HASH(_b0, _b1) (((_b0) * (_b1) ^ (_b1)) & 0xff)

constexpr const char *languages[256][MAX_LANG * 2 + 1] = {

	/* 0x00 */ {nullptr},
	/* 0x01 */ {"ro", "Romanian", nullptr},
	/* 0x02 */ {"sw", "Swahili", nullptr},
	/* 0x03 */ {"ne", "Nepali", nullptr},
	/* 0x04 */ {"nl", "Dutch", "sn", "Shona", nullptr},
	/* 0x05 */ {nullptr},
	/* 0x06 */ {"ln", "Lingala", nullptr},
	/* 0x07 */ {nullptr},
	/* 0x08 */ {"en", "English", "ie", "Interlingue", nullptr},
	/* 0x09 */ {"bg", "Bulgarian", "ha", "Hausa", nullptr},
	/* 0x0a */ {"cs", "Czech", "ko", "Korean", nullptr},
	/* 0x0b */ {nullptr},
	/* 0x0c */ {"gv", "Manx", nullptr},
	/* 0x0d */ {nullptr},
	/* 0x0e */ {nullptr},
	/* 0x0f */ {"vi", "Vietnamese", nullptr},
	/* 0x10 */ {"mt", "Maltese", nullptr},
	/* 0x11 */ {"bo", "Tibetan", "de", "German", "pa", "Panjabi", nullptr},
	/* 0x12 */ {nullptr},
	/* 0x13 */ {"lg", "Ganda", nullptr},
	/* 0x14 */ {nullptr},
	/* 0x15 */ {nullptr},
	/* 0x16 */ {nullptr},
	/* 0x17 */ {"tk", "Turkmen", nullptr},
	/* 0x18 */ {"gl", "Galician", "yo", "Yoruba", nullptr},
	/* 0x19 */ {nullptr},
	/* 0x1a */ {"sc", "Sardinian", nullptr},
	/* 0x1b */ {nullptr},
	/* 0x1c */ {"or", "Oriya", nullptr},
	/* 0x1d */ {nullptr},
	/* 0x1e */ {"fr", "French", nullptr},
	/* 0x1f */ {nullptr},
	/* 0x20 */ {"ae", "Avestan", "am", "Amharic", "mh", "Marshallese", nullptr},
	/* 0x21 */ {nullptr},
	/* 0x22 */ {"hr", "Croatian", "sg", "Sango", nullptr},
	/* 0x23 */ {"ps", "Pushto", "to", "Tonga", nullptr},
	/* 0x24 */ {"kj", "Kuanyama", "kv", "Komi", nullptr},
	/* 0x25 */ {"li", "Limburgan", "ng", "Ndonga", nullptr},
	/* 0x26 */ {nullptr},
	/* 0x27 */ {nullptr},
	/* 0x28 */ {nullptr},
	/* 0x29 */ {"lu", "Luba-Katanga", nullptr},
	/* 0x2a */ {"nn", "Norwegian Nynorsk", nullptr},
	/* 0x2b */ {nullptr},
	/* 0x2c */ {"es", "Spanish", "gn", "Guarani", "pl", "Polish", nullptr},
	/* 0x2d */ {nullptr},
	/* 0x2e */ {"om", "Oromo", nullptr},
	/* 0x2f */ {nullptr},
	/* 0x30 */ {nullptr},
	/* 0x31 */ {nullptr},
	/* 0x32 */ {nullptr},
	/* 0x33 */ {nullptr},
	/* 0x34 */ {nullptr},
	/* 0x35 */ {nullptr},
	/* 0x36 */ {nullptr},
	/* 0x37 */ {nullptr},
	/* 0x38 */ {nullptr},
	/* 0x39 */ {nullptr},
	/* 0x3a */ {"lb", "Luxembourgish", "se", "Northern Sami", nullptr},
	/* 0x3b */ {nullptr},
	/* 0x3c */ {nullptr},
	/* 0x3d */ {nullptr},
	/* 0x3e */ {nullptr},
	/* 0x3f */ {nullptr},
	/* 0x40 */ {"ab", "Abkhazian", "ar", "Arabic", "az", "Azerbaijani", nullptr},
	/* 0x41 */ {nullptr},
	/* 0x42 */ {"si", "Sinhala", nullptr},
	/* 0x43 */ {"ba", "Bashkir", nullptr},
	/* 0x44 */ {"sr", "Serbian", nullptr},
	/* 0x45 */ {"vo", "Volapuk", nullptr},
	/* 0x46 */ {nullptr},
	/* 0x47 */ {nullptr},
	/* 0x48 */ {"kl", "Kalaallisut", "th", "Thai", nullptr},
	/* 0x49 */ {nullptr},
	/* 0x4a */ {"cu", "Church Slavic", nullptr},
	/* 0x4b */ {"ja", "Japanese", nullptr},
	/* 0x4c */ {nullptr},
	/* 0x4d */ {nullptr},
	/* 0x4e */ {nullptr},
	/* 0x4f */ {"fy", "Western Frisian", nullptr},
	/* 0x50 */ {"ch", "Chamorro", nullptr},
	/* 0x51 */ {"hy", "Armenian", nullptr},
	/* 0x52 */ {nullptr},
	/* 0x53 */ {nullptr},
	/* 0x54 */ {"ht", "Haitian", nullptr},
	/* 0x55 */ {"fo", "Faroese", nullptr},
	/* 0x56 */ {"fj", "Fijian", nullptr},
	/* 0x57 */ {nullptr},
	/* 0x58 */ {"gd", "Scottish Gaelic", "ig", "Igbo", "is", "Icelandic", nullptr},
	/* 0x59 */ {nullptr},
	/* 0x5a */ {nullptr},
	/* 0x5b */ {"bi", "Bislama", "za", "Zhuang", nullptr},
	/* 0x5c */ {"eu", "Basque", nullptr},
	/* 0x5d */ {nullptr},
	/* 0x5e */ {nullptr},
	/* 0x5f */ {nullptr},
	/* 0x60 */ {"id", "Indonesian", nullptr},
	/* 0x61 */ {nullptr},
	/* 0x62 */ {"ks", "Kashmiri", nullptr},
	/* 0x63 */ {nullptr},
	/* 0x64 */ {"cr", "Cree", nullptr},
	/* 0x65 */ {nullptr},
	/* 0x66 */ {"ga", "Irish", "gu", "Gujarati", nullptr},
	/* 0x67 */ {nullptr},
	/* 0x68 */ {"st", "Southern Sotho", "ur", "Urdu", nullptr},
	/* 0x69 */ {nullptr},
	/* 0x6a */ {"ce", "Chechen", "kg", "Kongo", nullptr},
	/* 0x6b */ {nullptr},
	/* 0x6c */ {nullptr},
	/* 0x6d */ {"he", "Hebrew", nullptr},
	/* 0x6e */ {"dv", "Dhivehi", nullptr},
	/* 0x6f */ {"ru", "Russian", "ts", "Tsonga", nullptr},
	/* 0x70 */ {nullptr},
	/* 0x71 */ {nullptr},
	/* 0x72 */ {"bn", "Bengali", nullptr},
	/* 0x73 */ {nullptr},
	/* 0x74 */ {"sv", "Swedish", "ug", "Uighur", nullptr},
	/* 0x75 */ {"bs", "Bosnian", nullptr},
	/* 0x76 */ {"wa", "Walloon", nullptr},
	/* 0x77 */ {"ho", "Hiri Motu", nullptr},
	/* 0x78 */ {"ii", "Sichuan Yi", nullptr},
	/* 0x79 */ {nullptr},
	/* 0x7a */ {"sk", "Slovak", nullptr},
	/* 0x7b */ {nullptr},
	/* 0x7c */ {nullptr},
	/* 0x7d */ {nullptr},
	/* 0x7e */ {"nb", "Norwegian Bokmal", nullptr},
	/* 0x7f */ {nullptr},
	/* 0x80 */ {nullptr},
	/* 0x81 */ {nullptr},
	/* 0x82 */ {"co", "Corsican", nullptr},
	/* 0x83 */ {nullptr},
	/* 0x84 */ {"lt", "Lithuanian", "ms", "Malay", nullptr},
	/* 0x85 */ {"da", "Danish", nullptr},
	/* 0x86 */ {nullptr},
	/* 0x87 */ {"ny", "Nyanja", nullptr},
	/* 0x88 */ {"ik", "Inupiaq", "iu", "Inuktitut", "sd", "Sindhi", nullptr},
	/* 0x89 */ {"rw", "Kinyarwanda", nullptr},
	/* 0x8a */ {"ki", "Kikuyu", nullptr},
	/* 0x8b */ {nullptr},
	/* 0x8c */ {"uk", "Ukrainian", nullptr},
	/* 0x8d */ {"la", "Latin", nullptr},
	/* 0x8e */ {"nr", "South Ndebele", "oc", "Occitan", nullptr},
	/* 0x8f */ {nullptr},
	/* 0x90 */ {"ml", "Malayalam", nullptr},
	/* 0x91 */ {nullptr},
	/* 0x92 */ {"ku", "Kurdish", "rn", "Rundi", nullptr},
	/* 0x93 */ {nullptr},
	/* 0x94 */ {"kn", "Kannada", nullptr},
	/* 0x95 */ {"ta", "Tamil", nullptr},
	/* 0x96 */ {nullptr},
	/* 0x97 */ {nullptr},
	/* 0x98 */ {nullptr},
	/* 0x99 */ {"pi", "Pali", nullptr},
	/* 0x9a */ {"sm", "Samoan", nullptr},
	/* 0x9b */ {"tw", "Twi", nullptr},
	/* 0x9c */ {"nd", "North Ndebele", "oj", "Ojibwa", "tl", "Tagalog", nullptr},
	/* 0x9d */ {nullptr},
	/* 0x9e */ {nullptr},
	/* 0x9f */ {nullptr},
	/* 0xa0 */ {"aa", "Afar", "ay", "Aymara", nullptr},
	/* 0xa1 */ {"te", "Telugu", nullptr},
	/* 0xa2 */ {nullptr},
	/* 0xa3 */ {nullptr},
	/* 0xa4 */ {"eo", "Esperanto", nullptr},
	/* 0xa5 */ {nullptr},
	/* 0xa6 */ {nullptr},
	/* 0xa7 */ {nullptr},
	/* 0xa8 */ {"ia", "Interlingua", "xh", "Xhosa", nullptr},
	/* 0xa9 */ {nullptr},
	/* 0xaa */ {"jv", "Javanese", nullptr},
	/* 0xab */ {nullptr},
	/* 0xac */ {nullptr},
	/* 0xad */ {"ty", "Tahitian", nullptr},
	/* 0xae */ {"os", "Ossetian", nullptr},
	/* 0xaf */ {nullptr},
	/* 0xb0 */ {"et", "Estonian", nullptr},
	/* 0xb1 */ {nullptr},
	/* 0xb2 */ {"cy", "Welsh", "so", "Somali", "sq", "Albanian", nullptr},
	/* 0xb3 */ {nullptr},
	/* 0xb4 */ {"pt", "Portuguese", nullptr},
	/* 0xb5 */ {nullptr},
	/* 0xb6 */ {"tn", "Tswana", nullptr},
	/* 0xb7 */ {"zu", "Zulu", nullptr},
	/* 0xb8 */ {"bh", "Bihari", "mn", "Mongolian", "uz", "Uzbek", nullptr},
	/* 0xb9 */ {nullptr},
	/* 0xba */ {nullptr},
	/* 0xbb */ {"lo", "Lao", nullptr},
	/* 0xbc */ {"ee", "Ewe", "mg", "Malagasy", nullptr},
	/* 0xbd */ {nullptr},
	/* 0xbe */ {"lv", "Latvian", nullptr},
	/* 0xbf */ {"fi", "Finnish", nullptr},
	/* 0xc0 */ {"af", "Afrikaans", "an", "Aragonese", "av", "Avaric", nullptr},
	/* 0xc1 */ {"hi", "Hindi", nullptr},
	/* 0xc2 */ {"ff", "Fulah", "nv", "Navajo", nullptr},
	/* 0xc3 */ {nullptr},
	/* 0xc4 */ {nullptr},
	/* 0xc5 */ {nullptr},
	/* 0xc6 */ {nullptr},
	/* 0xc7 */ {"fa", "Persian", nullptr},
	/* 0xc8 */ {"yi", "Yiddish", nullptr},
	/* 0xc9 */ {nullptr},
	/* 0xca */ {"kw", "Cornish", nullptr},
	/* 0xcb */ {"tg", "Tajik", nullptr},
	/* 0xcc */ {nullptr},
	/* 0xcd */ {nullptr},
	/* 0xce */ {nullptr},
	/* 0xcf */ {"be", "Belarusian", "na", "Nauru", nullptr},
	/* 0xd0 */ {"qu", "Quechua", "sh", "Serbo-Croatian", nullptr},
	/* 0xd1 */ {nullptr},
	/* 0xd2 */ {"dz", "Dzongkha", "kk", "Kazakh", nullptr},
	/* 0xd3 */ {nullptr},
	/* 0xd4 */ {"cv", "Chuvash", "kr", "Kanuri", nullptr},
	/* 0xd5 */ {nullptr},
	/* 0xd6 */ {"br", "Breton", nullptr},
	/* 0xd7 */ {"bm", "Bambara", nullptr},
	/* 0xd8 */ {nullptr},
	/* 0xd9 */ {nullptr},
	/* 0xda */ {"ss", "Swati", "tr", "Turkish", nullptr},
	/* 0xdb */ {nullptr},
	/* 0xdc */ {"mi", "Maori", nullptr},
	/* 0xdd */ {"no", "Norwegian", nullptr},
	/* 0xde */ {nullptr},
	/* 0xdf */ {nullptr},
	/* 0xe0 */ {"ak", "Akan", "as", "Assamese", "it", "Italian", nullptr},
	/* 0xe1 */ {nullptr},
	/* 0xe2 */ {"ca", "Catalan", "km", "Central Khmer", nullptr},
	/* 0xe3 */ {nullptr},
	/* 0xe4 */ {"mk", "Macedonian", "tt", "Tatar", nullptr},
	/* 0xe5 */ {nullptr},
	/* 0xe6 */ {nullptr},
	/* 0xe7 */ {"rm", "Romansh", nullptr},
	/* 0xe8 */ {"io", "Ido", "sl", "Slovenian", nullptr},
	/* 0xe9 */ {nullptr},
	/* 0xea */ {"hz", "Herero", "ka", "Georgian", "ky", "Kirghiz", nullptr},
	/* 0xeb */ {"ve", "Venda", nullptr},
	/* 0xec */ {nullptr},
	/* 0xed */ {nullptr},
	/* 0xee */ {nullptr},
	/* 0xef */ {nullptr},
	/* 0xf0 */ {"el", "Modern Greek", nullptr},
	/* 0xf1 */ {nullptr},
	/* 0xf2 */ {"sa", "Sanskrit", nullptr},
	/* 0xf3 */ {nullptr},
	/* 0xf4 */ {nullptr},
	/* 0xf5 */ {nullptr},
	/* 0xf6 */ {"wo", "Wolof", nullptr},
	/* 0xf7 */ {nullptr},
	/* 0xf8 */ {"mr", "Marathi", "zh", "Chinese", nullptr},
	/* 0xf9 */ {nullptr},
	/* 0xfa */ {"su", "Sundanese", nullptr},
	/* 0xfb */ {nullptr},
	/* 0xfc */ {"my", "Burmese", nullptr},
	/* 0xfd */ {"hu", "Hungarian", "ti", "Tigrinya", nullptr},
	/* 0xfe */ {nullptr},
	/* 0xff */ {nullptr}

};

#endif
