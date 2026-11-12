// Copyright 2026 Кислов Роман Сергеевич
// SPDX-License-Identifier: Apache-2.0

package relay

// Profile describes an equipment format, not a promise that all firmware uses it.
type Profile struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	Pattern string `json:"regex"`
	Example string `json:"example"`
	Note    string `json:"note"`
	Source  string `json:"source,omitempty"`
}

func Profiles() []Profile {
	return []Profile{
		{"eltex", "Eltex ESR · TR-101 eth", `^(?:[^\x00-\x20]+ )?eth (?P<port>\d+(?:/\d+){1,2}):(?P<vlan>\d+)(?:[\x00-\x1f])?$`, "esr01 eth 1/0/1:120", "Текстовый формат TR-101. Иные форматы и бинарные Circuit ID требуют отдельного шаблона.", "https://docs.eltex-co.ru/pages/viewpage.action?pageId=55183793"},
		{"eltex-spv", "Eltex · slot/port:vlan", `^(?P<slot>\d+)/(?P<port>\d+):(?P<vlan>\d+)$`, "1/8:120", "Только для оборудования с включённым форматом spv и разделителями / и :.", "https://docs.eltex-co.ru/pages/viewpage.action?pageId=55183793"},
		{"qtech", "QTECH · VLAN+Ethernet", `^vlan(?P<vlan>\d+)\+Ethernet(?P<port>\d+/\d+/\d+)$`, "vlan120+Ethernet1/0/8", "Формат DHCP L3 relay из документации QTECH; проверьте серию и настройки устройства.", "https://www.qtech.ru/support/wiki/113/11253/"},
		{"usergate", "UserGate · свой шаблон", "", "", "Укажите шаблон по реальному Circuit ID. Если Option 82 отсутствует, настройте маршрутизацию по giaddr в доверенных relay.", "https://docs.usergate.com/nastrojka-dhcp-relay-i-osobennosti-raboty_643.html"},
		{"kontinent", "Код Безопасности / Континент · свой шаблон", "", "", "Формат зависит от версии и настройки Option 82. Нужен пример реального Circuit ID; без него используйте giaddr.", ""},
		{"snr", "SNR · свой шаблон", "", "", "Задайте шаблон по модели, прошивке и реальному Circuit ID.", ""},
		{"nateks", "NATEKS · свой шаблон", "", "", "Задайте шаблон по модели, прошивке и реальному Circuit ID.", ""},
		{"custom", "Другой производитель", "", "", "Регулярное выражение Go RE2 с именованной группой (?P<vlan>...).", ""},
	}
}
