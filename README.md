# Familienboard

Privates Statusboard für Haus, Finanzen, Familie, Auto und mehr. Einzelne Datei `index.html`, keine Installation.
Daten liegen in Supabase (Projekt „Protokoll“, Tabellen mit Präfix `fb_`).

## Zugang

Es gibt kein Passwort. Jede Person hat einen **persönlichen Zugangslink** (`…/?z=<Code>`). Beim ersten Öffnen
merkt sich der Browser den Code, danach reicht die normale Adresse. Den Link wie ein Passwort behandeln.

- Der Inhaber legt unter „Zugriff und Bereiche“ Personen an und wählt Rolle und sichtbare Bereiche.
- Rollen: **Inhaber** (alles), **Bearbeiten** (Themen anlegen/ändern/löschen), **Mitmachen** (Status setzen,
  abhaken, kommentieren; einfache Ansicht mit großer Schrift), **Ansehen** (nur lesen).
- Ein verlorener oder weitergegebener Link wird mit „Neuen Zugangslink erzeugen“ ersetzt, der alte ist dann ungültig.

## Sicherheit

Die Tabellen sind per Row Level Security gesperrt (keine Policies). Lesen und Schreiben geht nur über die
Funktionen `fb_*` (siehe `sql/001_familienboard.sql`), die den Zugangscode prüfen, Rollen und Bereiche erzwingen
und nur Hashes der Codes speichern. Gelöschte Themen, Bereiche und Personen werden nur ausgeblendet
(`geloescht` / `aktiv = false`).

## Funktionen

Übersicht mit Zählern, „Demnächst fällig“ (30 Tage), Bereichskarten, Themen mit Status (Handlungsbedarf,
Wartet, Läuft, Erledigt), nächstem Schritt, Fälligkeit, Zuständigem, Firma, Notiz, Links und Verlauf.
Wiederkehrende Themen (monatlich bis jährlich) werden beim Abhaken automatisch auf den nächsten Termin gesetzt.

## Hinweis zum SQL

`sql/001_familienboard.sql` dokumentiert den ersten Entwurf. Die endgültige Datenbank wurde in sechs
Migrationsschritten aufgebaut (u. a. Zugriff als Liste an der Person, Löschen als Ausblenden).
Die Tabelle `fb_zugriff` ist dadurch ungenutzt und kann gelegentlich entfernt werden.
