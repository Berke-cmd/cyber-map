# cyber-map

Neo4j ve OSINT tabanlı, Yapay Zekâ Destekli Dış Saldırı Yüzeyi Yönetimi (EASM) ve Tehdit İstihbaratı Motoru.

## Mimari ve Özellikler
* *Çoklu Kaynak Keşfi (OSINT):* DNS brute-force ve crt.sh Sertifika Şeffaflığı (Certificate Transparency) kayıtları üzerinden pasif subdomain tespiti.
* *Sunucu & Zafiyet İstihbaratı:* Shodan API entegrasyonu ile açık portlar, çalışan servisler ve bilinen CVE zafiyetlerinin çıkarılması.
* *Grafik Tabanlı Modelleme:* Domain, Subdomain, IP, Port, Servis ve CVE varlıklarının Neo4j üzerinde ilişkisel grafik ağı olarak haritalanması.
* *Yapay Zekâ Saldırı Rotası Analizi:* LLM analitiği ile kritik sızma rotalarının, MITRE ATT&CK tekniklerinin ve Blue Team savunma adımlarının raporlanması.

## Kullanılan Teknolojiler
* Python 3.10+
* Neo4j & Cypher Sorgu Dili
* Docker & Docker Compose
* OpenAI API & Shodan API

## Hızlı Başlangıç
1. Neo4j grafik veritabanını başlatın:
   ```bash
   docker-compose up -d
