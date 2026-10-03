# Оптимизация Ubuntu в Google Cloud

## Что исправлено

Раньше полная оптимизация Ubuntu amd64 автоматически ставила XanMod x64v3,
пересобирала его initramfs и выбирала его в GRUB. Финальная проверка повторяла
установку/выбор, а аудит считал отсутствие XanMod недостающей оптимизацией.
Проверка CPU x86-64-v3 и наличия файлов ядра не доказывает, что оно загрузит VM
с её диском, сетевым адаптером и настройками Secure Boot.

Для Google Cloud теперь:

- Используется штатное ядро; установка XanMod, подключение его репозитория,
  пересборка его initramfs и выбор его в GRUB заблокированы.
- Облако определяется локально по `*-gcp`/`*-gke`, DMI или DataSourceGCE.
  Сеть и metadata API для этой проверки не нужны. DMI/cloud-init позволяют
  распознать GCE и после загрузки пользовательского ядра.
- Если остались ядро, незавершённый пакет XanMod или `99-kto-xanmod.cfg`,
  оптимизация останавливается **до** `dpkg --configure -a` и установки пакетов.
  Самостоятельно удалять ядра или переписывать загрузчик она не будет.
- Во всех режимах сохраняются SSH-порт/ключи, DNS и IPv6. Неактивный UFW не
  включается автоматически. Это не открывает порты в firewall Google Cloud.
- Аудит не предлагает установить XanMod. Нет безусловного совета перезагрузиться.
- Остальные этапы (пакеты, BBR/FQ, лимиты, conntrack, память, хранение,
  HAProxy и AntiScanner) остаются. Это не режим полного отсутствия изменений.

На других VPS поведение установки XanMod не изменено. Старые изменения DNS,
SSH, IPv6 и загрузчика на уже оптимизированных VM автоматически не отменяются.
Обычные обновления ядра Ubuntu/APT также не блокируются.

## Если VM уже не загружается

Не запускай оптимизацию повторно и не удаляй вслепую `linux-*`.
Сначала сделай snapshot загрузочного диска в Google Cloud. Затем открой
Compute Engine -> VM -> Serial port 1 output. Нужны строка `Linux version`,
строка `Kernel panic` и примерно 50 строк перед ней.

Через Cloud Shell можно сохранить вывод (подставь свои PROJECT, VM, ZONE):

```bash
gcloud compute instances get-serial-port-output VM \
  --project=PROJECT --zone=ZONE --port=1
```

Если доступен интерактивный GRUB через Serial console, в Advanced options
выбери ранее рабочее ядро Ubuntu `*-gcp`, не XanMod. Это однократный выбор:
сохранённая запись XanMod может остаться выбранной для следующей перезагрузки.

Если меню недоступно или рабочего ядра нет, используй восстановление boot disk
через временную VM по инструкции Google. **Команды ремонта нужно выполнять
в окружении повреждённого диска, а не на загрузочном диске временной VM.**
Нужны проверка установленных `linux-gcp`, initramfs, GRUB и его saved entry.
Один `rm 99-kto-xanmod.cfg` не гарантирует выбора штатного ядра: более новое
стороннее ядро может остаться первым пунктом меню.

После успешной загрузки собери диагностику без изменения настроек:

```bash
uname -r
cat /sys/class/dmi/id/product_name
df -h / /boot
dpkg-query -W -f='${binary:Package} ${Status}\n' 'linux-*gcp*' 'linux-*xanmod*'
sudo grep -HnE 'GRUB_DEFAULT|GRUB_SAVEDEFAULT' /etc/default/grub /etc/default/grub.d/*.cfg
sudo grub-editenv /boot/grub/grubenv list
sudo tail -n 100 /var/log/kto-tune.log
```

Без boot log замена ядра остаётся вероятным подозреваемым, не установленной
причиной конкретной паники. Если ядро загрузилось, но SSH недоступен, отдельно
проверяются sshd, VPC firewall, OS Login, guest agent и настройки сети.

## Проверка исправления

Автотесты проверяют распознавание GCE, запрет всех входов в установку/выбор
XanMod, раннюю остановку при старых артефактах, пропуск изменений DNS/IPv6/SSH
и выполнение остальных шагов с подменёнными системными командами.
Это не тест настоящей загрузки GCE. Перед массовым запуском проверь отдельную
тестовую Ubuntu 24.04 VM со snapshot и доступной Serial console: сравни
`uname -r`, настройки GRUB, SSH и сеть до/после оптимизации и тестового reboot.

## Источники

- [Ubuntu: штатные ядра GCP](https://ubuntu.com/gcp/docs/google-explanation/canonical-offerings/)
- [Google: kernel panic и восстановление загрузки](https://docs.cloud.google.com/compute/docs/troubleshooting/kernel-panic)
- [Google: интерактивная Serial console](https://docs.cloud.google.com/compute/docs/troubleshooting/troubleshooting-using-serial-console)

