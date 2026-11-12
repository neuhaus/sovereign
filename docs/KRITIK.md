# Kritik und Verbesserungsvorschläge zur Debian-13-Modernisierung

Stand: 7. November 2026, Branch `trixie-wip` bei `e17e03b`.

## Einschätzung

Ich würde die Grundarchitektur beibehalten, aber vor Phase 6 eine Phase zur
Betriebsreife einschieben. Der Branch ist ein weitgehender Neubau mit
durchdachten Entscheidungen und umfangreichen Integrationstests. Die größten
verbleibenden Risiken liegen beim Übergang vom funktionierenden Testaufbau zum
dauerhaften Betrieb: Migration, Rechtebegrenzung, Widerruf von Zugängen und
verlässliche Fehlermeldungen.

Diese Einschätzung beruht auf der Untersuchung von `docs/PLAN.md`,
`docs/STATUS.md`, Rollen, Testcode und Betriebsanleitungen. Die dokumentierten
263 Tests wurden für diese Begutachtung nicht erneut ausgeführt; Incus und
Molecule standen in der Review-Umgebung nicht zur Verfügung. Wo ein Befund nur
aus dem Code abgeleitet ist, ist dies entsprechend gekennzeichnet.

## Was ich beibehalten würde

Debian-Pakete, systemd, SQLite und die deutliche Verkleinerung des alten Stacks
passen zum Ziel eines kleinen, selbst betriebenen Mailservers. Auch der Verzicht
auf lokales ClamAV ist unter der vorgegebenen Speichergrenze nachvollziehbar.
Besonders überzeugend sind die Tests mit echtem Mailfluss, eigenem DNS, Pebble,
Gegenstellen und Wiederherstellung auf einer frischen Instanz. Das prüft
wesentlich mehr als das Vorhandensein von Konfigurationsdateien.

Die dokumentierten Erkenntnisse zu Dovecot 2.4, SQLite, Ansible-Variablen und
Paketunterschieden zeigen sorgfältige Arbeit. Die Kritik richtet sich deshalb
vor allem gegen einige Sicherheitsgrenzen und gegen die Reihenfolge der
nächsten Schritte.

## 1. Migration vor weiteren Funktionen absichern

Hier liegt das unmittelbar größte Datenverlustrisiko. Die
[Migrationsanleitung](MIGRATION.md) setzt global `mail_driver=imapc` und verwendet
gleichzeitig `imapc:` als Gegenstelle. Damit wird auch die eigentlich lokale
Mailbox auf das IMAP-Backend umgestellt. Das sollte vor Verwendung korrigiert
und praktisch geprüft werden.

Noch kritischer ist die Empfehlung, nach dem DNS-Wechsel nochmals zu
synchronisieren: Der zuvor beschriebene Befehl `backup -R` macht das Ziel zum
Abbild der Quelle und kann inzwischen ausschließlich auf dem neuen Server
eingetroffene Nachrichten löschen. Dovecot empfiehlt für diesen Fall
ausdrücklich `sync -1`. Siehe die
[Dovecot-Migrationsdokumentation](https://doc.dovecot.org/2.4.1/core/admin/migration.html#executing-migration-1).

**Vorschlag:** Einen kleinen, reproduzierbaren Migrationstest ergänzen: alte
Mailbox, Erstübernahme, anschließend neue Nachrichten auf beiden Seiten,
abschließender Abgleich. Dabei Nachrichteninhalt, Flags, Ordner und Abonnements
prüfen. Geheimnisse gehören in eine geschützte temporäre Konfiguration;
Shell-History nachträglich zu löschen ist als Standardanleitung unzureichend.

„Keine automatisierte Migration“ ist eine vertretbare Umfangsentscheidung. Eine
getestete manuelle Migration ist trotzdem eine Voraussetzung für die Ablösung
des alten Sovereign.

## 2. Unvollständige Backups nicht als erfolgreich melden

Das [Backup-Skript](../roles/restic/templates/sovereign-backup.j2) akzeptiert
Restic-Exitcode 3 und aktualisiert anschließend
`sovereign_backup_last_success_timestamp_seconds`. Der Kommentar führt dies auf
umbenannte Maildir-Dateien zurück. Diese Erklärung ist zu eng: Exitcode 3
umfasst allgemein nicht lesbare Quelldateien, beispielsweise wegen
Berechtigungs- oder Lesefehlern. Der Snapshot ist dann unvollständig. Siehe
[Restics Beschreibung der Exitcodes](https://restic.readthedocs.io/en/stable/040_backup.html#exit-status-codes).

Dadurch könnte gerade der vorgesehene Alarm dauerhaft ausbleiben.

**Vorschlag:** Den letzten vollständig erfolgreichen Lauf nur bei Exitcode 0
aktualisieren. Zusätzlich letzten Versuch, Ergebnis und gegebenenfalls
unvollständige Sicherung exportieren. Falls bestimmte Maildir-Rennen toleriert
werden sollen, müssen sie ausdrücklich erkannt werden; sämtliche Lesefehler
pauschal zu akzeptieren reicht dafür nicht.

Ergänzen würde ich regelmäßige Integritätsprüfungen und einen dokumentierten
Wiederherstellungszeitraum: tägliche Sicherung bedeutet potenziell ungefähr
einen Tag verlorene Änderungen. Der vorhandene Wiederherstellungstest ist eine
gute Grundlage.

## 3. Kontensperren und Widerruf auf bestehende Sitzungen ausdehnen

Beim administrativen Passwortreset werden offene Dovecot-Sitzungen ausdrücklich
beendet. Die [Berechnung dieser Benutzerliste](../roles/maildb/templates/reset-addresses.json.j2)
berücksichtigt jedoch ausschließlich geänderte Haupthashes.

Entfernte oder deaktivierte Konten sowie widerrufene App-Passwörter lösen diesen
Mechanismus nicht aus. Neue Logins scheitern anschließend, aber bereits
authentifizierte Verbindungen werden durch die Datenbankänderung allein nicht
ausdrücklich beendet. Die Tests prüfen beim Entfernen eines Kontos bislang
einen neuen Login. Das Verhalten bestehender Verbindungen wurde in dieser
Begutachtung nicht praktisch reproduziert.

**Vorschlag:** Einen gemeinsamen Ablauf für Zugangswiderruf definieren: Konto
löschen, Konto deaktivieren, Passwort zurücksetzen und App-Passwort entfernen.
Wenn die verwendete App-Zugangsdatenkennung einer Sitzung nicht zugeordnet
werden kann, bei deren Widerruf konservativ alle Sitzungen des Kontos beenden.

Das sollte auch die gewünschte Behandlung bestehender Roundcube-Sitzungen
klären. Ein Passwortwechsel und eine vollständige Kontosperre sind
unterschiedliche administrative Vorgänge.

## 4. Roundcubes Rechte auf das notwendige Maß beschränken

Die Entscheidung ist im Plan offen beschrieben, dennoch würde ich sie ändern:
Roundcube darf für Passwortänderungen die gesamte Kontendatenbank schreiben.
Ein kompromittierter PHP-Prozess könnte dadurch auch fremde Passwörter,
Weiterleitungen und Konten ändern. SQLite bietet hier keine datenbankinternen
Tabellenrechte.

Vorgeschaltete Basic Auth reduziert die öffentliche Angriffsfläche. Sie begrenzt
jedoch nicht die Folgen einer Schwachstelle, die nach erfolgreicher Anmeldung
ausgelöst wird. „Benutzer sind vertrauenswürdig“ schützt auch nicht vor
manipulierten Nachrichten oder übernommenen Benutzerzugängen.

**Vorschlag:** Die Passwortänderung durch einen eng begrenzten lokalen Dienst
ausführen lassen. Dieser sollte das aktuelle Hauptpasswort selbst prüfen und
ausschließlich das Passwort des dazugehörigen Kontos ändern können. Roundcube
bekäme keine Schreibrechte auf die Kontendatenbank.

Das ist zusätzliche Eigenentwicklung und muss bewusst abgewogen werden. Bis
dahin würde ich das verbleibende Risiko ausdrücklich als systemweite
Kontenkompromittierung beschreiben. Basic Auth als zusätzliche Hürde kann
trotzdem sinnvoll bleiben.

## 5. Grenzfälle der eigenen DANE/MTA-STS-Logik prüfen

Der Wunsch, DANE-Vorrang sicherzustellen, ist richtig. Die
[Implementierung](../roles/mta_sts/files/sovereign-tls-policy) schaltet MTA-STS
für die gesamte Empfängerdomain aus, sobald irgendein untersuchter MX einen
authentifizierten TLSA-Eintrag besitzt.

Daraus ergibt sich ein wichtiger Grenzfall: Eine Domain besitzt mehrere MX,
aber nur einige unterstützen DANE. Bei Ausfall des DANE-MX könnte Postfix einen
anderen MX ohne TLSA verwenden, während die MTA-STS-Policy bereits insgesamt
ausgeblendet wurde. Zudem berücksichtigt die Entscheidung nur die ersten zehn
MX und prüft die Verwendbarkeit der TLSA-Einträge nicht.

Das ist eine aus dem Code abgeleitete Risikobewertung, kein hier reproduzierter
Zustellversuch. [RFC 8461, Abschnitt 2](https://www.rfc-editor.org/rfc/rfc8461.html#section-2)
verlangt, fehlgeschlagene DANE-Prüfungen nicht durch MTA-STS zu übersteuern;
daraus folgt nicht unmittelbar, dass ein einzelner TLSA-Eintrag die Policy für
sämtliche MX ersetzen sollte.

**Vorschlag:** Gemischte MX-Konfigurationen, Ausfälle, unbrauchbare
TLSA-Einträge, DNS-Fehler und abgelaufene Policies gezielt testen. Diese
Eigenentwicklung würde ich als eigenständige Sicherheitskomponente behandeln:
mit festgelegter Semantik, kleinen automatisierten Tests und einer
dokumentierten Entscheidung für jeden Fehlerfall.

## 6. Konfigurationsversprechen und Fehlerbehandlung vervollständigen

### Quotas

`quota_mb` wird dokumentiert, gespeichert und synchronisiert. Die
[Dovecot-Konfiguration](../roles/dovecot/templates/dovecot.conf.j2) liest den
Wert jedoch nicht aus und aktiviert kein Quota-Plugin. Ein gesetztes Limit wird
somit derzeit nicht durchgesetzt. Entweder vollständig implementieren und
testen oder die Option vorerst zurückweisen.

### Schutz vor SSH-Aussperrung

Die [SSH-Rolle](../roles/openssh/tasks/main.yml) prüft nur, ob `authorized_keys`
existiert und nicht leer ist. Das beweist keinen benutzbaren Schlüssel:
Kommentare, ungültige Einträge, falsche Rechte oder Schlüsselbeschränkungen
können trotzdem zur Aussperrung führen. Sinnvoll wären die Prüfung der
effektiven Gesamtkonfiguration und eine unabhängige neue Anmeldung mit dem
vorgesehenen Administrationsschlüssel.

### Zertifikatsübernahme

Der [Certbot-Deploy-Hook](../roles/certbot/templates/sovereign-reload.j2) sollte
Fehler weitergeben: Aktuell werden fehlgeschlagene Reloads protokolliert,
anschließend aber trotzdem der Deployment-Zeitpunkt geschrieben.
Zertifikatsausstellung und erfolgreiche Übernahme durch die Dienste brauchen
getrennte Erfolgsaussagen.

## 7. Wartungsarmut durch einen engeren Supportvertrag absichern

Debian Testing als zusätzlicher Testkanal ist wertvoll. Als gleichrangiges
Produktionsziel erhöht es den Pflegeaufwand erheblich. Ich würde Debian 13 als
verbindliches Betriebsziel festlegen und Testing zunächst als Frühwarnsystem
führen.

Dazu gehören:

- Eine festgelegte, in CI geprüfte Kombination aus Controller-Python, Ansible
  und Collections; reine Mindestversionen machen spätere Testläufe schwer
  vergleichbar.
- Reproduzierbare VM-Prüfungen für Boot, Resolver, Zeitsynchronisation und
  Wiederanlauf.
- Tests unter gleichzeitiger Last: IMAP-Anmeldungen, PHP, Volltextindexierung
  und Backup.
- Mitgelieferte Alarmbeispiele für Mailqueue, Plattenplatz, Inodes,
  Zertifikatsablauf und Backupfehler.

Allein fünf PHP-Prozesse mit jeweils 256 MiB Speicherlimit zeigen, weshalb der
freie Speicher nach einem Testlauf noch kein Nachweis für den Betrieb mit
2 GiB ist. Die tatsächlichen Spitzen sollten gemessen werden.

Den bekannten Resolver-Socket-Fehler würde ich vor dem nächsten Ausbau beheben.
Außerdem widerspricht der ältere Satz „alle VM-Tests bestehen“ im
[Statusdokument](STATUS.md) dem neueren dokumentierten Fehler. Solche Aussagen
sollten einen eindeutigen Stand haben.

Auch den Anspruch „BSI-konform“ würde ich vorerst präzisieren: etwa
„TLS-Konfiguration an den genannten BSI-Empfehlungen orientiert“, solange keine
nachvollziehbare Zuordnung der Anforderungen zu Umsetzung und Nachweisen
vorliegt.

## 8. Die nächste Veröffentlichung an Betriebsreife knüpfen

Phase 6 fügt Routing, Tunnel, NAT, MTU-Probleme und einen zweiten Ausfallort
hinzu. Die Abhängigkeit von einem konkreten OpenVZ-Angebot vergrößert die
Varianten zusätzlich. Vor dem ersten realen Betrieb des bestehenden Stacks
wäre mir das zu viel neue Unsicherheit.

Ich würde die nächsten Schritte so ordnen:

| Reihenfolge | Ergebnis |
|---|---|
| 1 | Migration, Backup-Erfolg und Zugangswiderruf korrigiert und getestet |
| 2 | Quotas, Zertifikatsübernahme und SSH-Zugang zuverlässig abgesichert |
| 3 | DANE/MTA-STS-Grenzfälle und Roundcube-Berechtigungen entschieden |
| 4 | Debian-13-Pilotbetrieb mit Neustart, Updates, Alarmen und Wiederherstellung |
| 5 | Optionale Rollen mit vollständigem Deaktivierungsablauf |
| 6 | Gateway und Heimserver über WireGuard |

Die bereits vorgesehenen Deaktivierungsabläufe würde ich vorziehen: Ein kleiner
Mailserver sollte ohne Webmail und Groupware betreibbar sein. Bei Backups würde
ich zwischen „Restic deaktivieren“ und „bewusst extern gesichert“ unterscheiden,
damit das gute Ziel einer verpflichtenden Sicherung erhalten bleibt.

Meine zentrale Änderung am Plan wäre damit eine andere Definition von
„fertig“: Zusätzlich zu Konvergenz, Idempotenz und erfolgreichem Mailfluss müssen
Migration, Ausfall, Widerruf und Wiederherstellung belastbar funktionieren. Die
bestehende Architektur und Testbasis sind dafür gut geeignet; dort würde ich
jetzt investieren.
