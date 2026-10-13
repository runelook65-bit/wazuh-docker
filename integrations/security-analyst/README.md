# Security Analyst — Wazuh dosya aktarımı

Bu adaptör canlı bağlantı kurmaz. Wazuh JSONL kayıtlarını yerel dosyada hazırlar;
yükleme kullanıcı tarafından Security Analyst panelinde yapılır. Ham alarm kayıtları
hassas alanlar içerebilir. Gerçek kayıtları bu public repoya eklemeyin.

Fork: https://github.com/runelook65-bit/wazuh-docker
Başlangıç dalı: security-analyst/starter-v1
İncelenen kaynak: 635adbd39cd1d8b6ab40c7f91582eec9837ff72d

Wazuh main geliştirme dalıdır. Bu paket Docker kurulumunu başlatmaz ve servis,
sertifika, ağ ya da erişim ayarı değiştirmez. Gerçek ortam kurulumu ayrıca seçilmiş
bir Wazuh sürümü ve o sürümün resmi dokümantasyonuyla yapılmalı.

## Yerel dosya hazırlama

Site checkout'unda:

```sh
python3 scripts/export-wazuh-alerts.py /yerel/yol/alerts.json --limit 1000 > security-analyst.jsonl
```

Fork checkout'unda:

```sh
python3 integrations/security-analyst/export-alerts.py /yerel/yol/alerts.json --limit 1000 > security-analyst.jsonl
```

Girdi, Wazuh manager'dan yerel olarak elde edilmiş alerts.json / JSONL olmalı.
Script dosyadaki son N satırı seçer (zaman damgasına göre sıralamaz), alanları
korur ve kaç eski satırın dışarıda kaldığını stderr'e yazar. En fazla 10.000 kayıt
ve 10 MB çıktı. Bozuk satır, Wazuh dışı kayıt veya büyük çıktı tüm aktarımı durdurur;
başarısızlıkta stdout'a kısmi JSON yazılmaz. Veri internete gönderilmez.

Panelde Kayıt yükle ile çıktıyı aç. Timestamp saat dilimiyle bulunmalı. İlk Sigma
paketi yalnızca şu Windows süreç başlangıç kayıtlarını kullanır:

| Wazuh alanı | Panel alanı |
| --- | --- |
| data.win.system.providerName + channel + eventID | Windows Sysmon 1 veya Security 4688 kaynak kontrolü |
| data.win.eventdata.image / newProcessName | process_image |
| data.win.eventdata.originalFileName | process_original_file_name |
| data.win.eventdata.commandLine | command_line |

Süreç kaynağı doğrulandığında platform=windows atanır. Sadece command_line
bulunması süreç kimliği yerine kullanılmaz. agent.ip giriş kaynağı olarak alınmaz.

synthetic-alerts.jsonl: altı sentetik Sysmon kaydı, üç Sigma eşleşmesi (Certutil bir,
Mshta iki) ve üç negatif örnek. example.invalid adresleri ve komutlar metindir;
hiçbiri çalıştırılmaz. Bu örnekler gerçek Wazuh/Sysmon kurulumu doğrulaması değildir.
