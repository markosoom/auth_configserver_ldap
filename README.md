# ContainerSSH Auth & Config Webhook Server with LDAP Integration

[![ContainerSSH](https://img.shields.io/badge/Powered%20by-ContainerSSH-blue)](https://containerssh.io/)
See projekt implementeerib [ContainerSSH](https://containerssh.io/) jaoks autentimise ja konfiguratsiooni webhook-serveri, mis kasutab **OpenLDAP** taustaprogrammi. See võimaldab kasutajatel autentida nii parooli kui ka SSH avaliku võtmega, mis on salvestatud LDAP-i, ning dünaamiliselt konfigureerida kasutajapõhiseid konteinereid.

ContainerSSH käivitab iga SSH-ühenduse jaoks uue konteineri (Kuberneteses, Podmanis või Dockeris). Kasutaja suunatakse läbipaistvalt konteinerisse, mis eemaldatakse ühenduse katkemisel. See server muudab autentimise ja konteineri seadistamise dünaamiliseks, ilma et oleks vaja süsteemseid kasutajaid host-masinas.

**Põhifunktsioonid:**

* LDAP-põhine parooliautentimine.
* LDAP-põhine avaliku võtme autentimine (kasutades `sshPublicKey` atribuuti).
* Dünaamiline kasutajapõhine konteineri konfiguratsioon (nt erinevad Docker image'id: ubuntu, alpine jne).

---

**Sisukord:**

* [⚠️ Olulised Turvahoiatused](#️-olulised-turvahoiatused)
* [🔧 Eeldused](#-eeldused)
* [⚙️ Seadistamine](#️-seadistamine)
    * [Keskkonnamuutujad](#keskkonnamuutujad)
    * [Võtmefailide Ettevalmistamine](#võtmefailide-ettevalmistamine)
* [🚀 Käivitamine](#-käivitamine)
    * [Kompileerimine](#kompileerimine)
    * [Serveri Käivitamine](#serveri-käivitamine)
* [🔌 ContainerSSH Konfigureerimine](#-containerssh-konfigureerimine)
* [🧪 Testimine](#-testimine)
    * [SSH Ühenduse Testimine](#ssh-ühenduse-testimine)
    * [Otsene API Testimine (`curl`)](#otsene-api-testimine-curl)
* [🐳 Docker Image Ehitamine](#-docker-image-ehitamine)
* [☸️ Kubernetes Deployment](#️-kubernetes-deployment)
* [💡 Täiendavad Märkused](#-täiendavad-märkused)
    * [LDAP Struktuur](#ldap-struktuur)
    * [Dünaamiline Võtme Lisamine](#dünaamiline-võtme-lisamine)
    * [Avaliku Võtmega Autentimise Keelamine](#avaliku-võtmega-autentimise-keelamine)
* [🤝 Kaastöö](#-kaastöö)
* [📜 Litsents](#-litsents)

---

## ⚠️ Olulised Turvahoiatused

* **TLS/StartTLS:** See näidiskood **ei kasuta vaikimisi TLS/StartTLS-i** LDAP ühenduste jaoks ega pruugi sisaldada piisavat veatöötlust. **Ära kasuta seda koodi tootmises ilma turvalise ühenduse (TLS/StartTLS) ja põhjaliku veatöötluseta!**
* **LDAP Bind:** Näide kasutab lihtsat bindi parooliga autentimiseks. Kui anonüümne otsing pole LDAP serveris lubatud, võib vaja minna teenusekonto (service account) seadistamist (`LDAP_BIND_DN` ja `LDAP_BIND_PASSWORD`), et otsida kasutaja atribuute (nagu `sshPublicKey`). Veendu, et teenusekontol oleksid minimaalsed vajalikud õigused.
* **TLS Verify Skip:** `LDAP_SKIP_TLS_VERIFY` on näites seatud `true`-ks testimise lihtsustamiseks. **Tootmises peab see ALATI olema `false`!** Selle `true`-ks jätmine muudab ühenduse haavatavaks Man-in-the-Middle (MitM) rünnakute suhtes.
* **Konfiguratsiooni Haldus:** Keskkonnamuutujate kasutamine tundliku info (nagu bind paroolid) jaoks ei pruugi olla kõige turvalisem meetod. Kaalu turvalisemaid konfiguratsioonihaldusvahendeid (nt Vault, Kubernetes Secrets jms) tootmiskeskkondades.

## 🔧 Eeldused

Enne alustamist veendu, et sul on olemas:

* Go (soovitatavalt vastavalt versioonile mis on koodis)
* Ligipääs OpenLDAP serverile. Võimalik kasutada anonümuus bind-ikut kui ka read-only user bind-ingut.
* ContainerSSH paigaldatud ja konfigureeritud (Kubernetes, Docker või Podman).
* `docker` ja `docker buildx` (kui ehitad Docker imaget).
* `kubectl` (kui kasutad Kubernetes't).

## ⚙️ Seadistamine

1.  **Klooni repositoorium (või lae kood alla):**
    ```bash
    git clone <repo-url>
    cd <repo-kaust>
    ```
2.  **Initsialiseeri Go moodul (vajadusel):**

    Kui `go.mod` fail puudub:
    ```bash
    go mod init auth_configserver_ldap
    ```
    Seejärel lae alla sõltuvused:
    ```bash
    go mod tidy
    ```
    Kompileerimine
    ```bash
    go build -o auth_configserver_ldap .
    ```

3. **Keskkonnamuutujad:**

Seadista järgmised keskkonnamuutujad vastavalt oma LDAP ja soovitud serveri konfiguratsioonile.
Tekita env fail. Muutujaid saab laadida
```bash
source env
```

```bash
# Serveri aadress ja port
export LISTEN_ADDR=":8888"

# --- LDAP Seaded ---
export LDAP_HOST="sinu-ldap-server.com"
export LDAP_PORT="636" # Tavaliselt 389 (LDAP) või 636 (LDAPS)
export LDAP_USE_TLS="true" # Kasuta 'true' LDAPS jaoks või StartTLS jaoks
export LDAP_START_TLS="false" # Kasuta 'true' StartTLS jaoks (kui LDAP_USE_TLS=false)
export LDAP_SKIP_TLS_VERIFY="true" # !! AINULT TESTIMISEKS !! Tootmises sea 'false'

# LDAP Base DN ja otsingumallid
export LDAP_BASE_DN="dc=sinudomeen,dc=com"
export LDAP_USER_DN_TEMPLATE="uid=%s,ou=users,dc=sinudomeen,dc=com" # Mall kasutaja DN leidmiseks (asendab %s kasutajanimega)
export LDAP_SEARCH_FILTER_TEMPLATE="(uid=%s)" # Mall kasutaja otsimiseks (asendab %s kasutajanimega)
export LDAP_SSH_PUBLIC_KEY_ATTR="sshPublicKey" # Atribuut, kus hoitakse kasutaja avalikke võtmeid

# LDAP Service Account (vajalik, kui anonüümne bind pole lubatud atribuutide lugemiseks)
export LDAP_BIND_DN="uid=readonly,dc=serviceaccount,dc=sinudomeen,dc=com" # Teenuskonto DN
export LDAP_BIND_PASSWORD="teenuskonto_parool"      # Teenuskonto parool

# --- Konfiguratsiooniserveri Seaded ---
# See on lisavõimalus, kui ldap publickey-d ei saa ldap serverist hankida.
# Kaust serveris, kust otsitakse kasutaja avaliku võtme faile (vajalik /config endpointi jaoks)
export CONFIG_KEY_PATH_BASE="/etc/containerssh/userkeys"
# Failinime mall kasutaja võtmefaili jaoks (asendab %s kasutajanimega)
export CONFIG_KEY_FILENAME_TEMPLATE="%s.pub"

# Vaikimisi konteineri seaded (kui LDAP-ist ei tule spetsiifilist konfiguratsiooni)
export DEFAULT_DOCKER_IMAGE="ubuntu:latest"
export DEFAULT_SHELL_COMMAND="/bin/bash"
```
4. **Võtmefailide ettevalmistamine**

Kui soovid kasutada dünaamilist võtme lisamist /config endpointi kaudu:

Loo serveris kaust, mille määrasid CONFIG_KEY_PATH_BASE muutujaga (nt /etc/containerssh/userkeys). Kasuta volumomount-i
Paiguta sinna kasutajate avalike võtmete failid. Failinimed peavad vastama CONFIG_KEY_FILENAME_TEMPLATE mustrile (nt kasutajanimi.pub).
Iga faili sisu peab olema OpenSSH authorized_keys formaadis avalik võti (nt ssh-rsa AAAAB3NzaC1yc2... kasutaja@host).
Märkus: See samm on vajalik ainult siis, kui soovid, et konfiguratsiooniserver lisaks võtme konteinerisse. Autentimiseks kasutatakse endiselt LDAP-is olevat sshPublicKey atribuuti.

Avaliku võtme tekitamine:
```sh
ssh-keygen -t ed25519 -f kasutajanimi -N ""
```
Avaliku võtmega logimine:
```sh
ssh -i kasutajanimi kasutajanimi@containerssh-host -p <port>
```

### 🚀 Käivitamine
1. **Serveri käivitamine**

```bash
./auth_configserver_ldap
```
Server hakkab kuulama LISTEN_ADDR muutujaga (muutujad sai määrata env failiga) määratud aadressil ja pordil (nt :8888). Jälgi logisid võimalike vigade osas.

### 🔌 ContainerSSH konfigureerimine

Muuda oma ContainerSSH konfiguratsioonifaili (containerssh.yaml vms), et see kasutaks seda webhook-serverit autentimiseks ja/või konfigureerimiseks. Asenda http://127.0.0.1:8888 serveri tegeliku aadressiga, kui see jookseb teises masinas või pordil.

```yaml
log:
  level: debug # Hea testimise ajal
ssh:
  hostkeys:
    - /etc/containerssh/host.key # ContainerSSH hostivõti

# --- Autentimine ---
auth:
  password:
    method: webhook
    webhook:
      # Kasuta service nime, kui jookseb Kubernetesis, muidu IP/hostinime
      url: http://auth-config-server.default.svc.cluster.local:8888/password # Parooliautentimise endpoint
      timeout: 5s
      # passwordAuthFailedAttempts: 3
      # passwordAuthFailureDelay: 2s
  publicKey:
    method: webhook
    webhook:
      url: http://auth-config-server.default.svc.cluster.local:8888/pubkey # Avaliku võtme autentimise endpoint
      timeout: 5s
      # pubKeyAuthFailedAttempts: 3
      # pubKeyAuthFailureDelay: 2s

# --- Konfiguratsioon (valikuline) ---
configserver:
  url: http://auth-config-server.default.svc.cluster.local:8888/config # Konfiguratsiooni endpoint
  timeout: 5s
  # clientTimeout: 30s
```
Tähtis: Veendu, et ContainerSSH protsessil (nt Pod Kubernetesis) oleks võrguühendus sinu auth_configserver_ldap serveriga (selle Service'i või IP kaudu).

### 🧪 Testimine
SSH Ühenduse Testimine

Proovi ühenduda ContainerSSH kaudu, kasutades kasutajanime ja parooli või avalikku võtit, mis on LDAP-is olemas. Parooliga autentimisel keela eelnevalt public võtmega logimine. 

```bash
# Parooliga
ssh kasutajanimi@containerssh-host -p <port>
```
Avaliku võtmega (veendu, et kohalik võti vastab LDAP-is olevale, vajadusel lisa ldap serverile sshpubkey tugi)

```bash
ssh -i ~/.ssh/sinu_privaatvõti kasutajanimi@containerssh-host -p <port>
```
Jälgi ./auth_configserver_ldap logisid ja ContainerSSH logisid, et näha autentimis- ja konfiguratsioonipäringuid ning võimalikke vigu. Kui konfigureerisid võtme lisamise, kontrolli konteinerisse sisse logides, kas vastav avalik võti on lisatud ~/.ssh/authorized_keys faili.

Otse API vastu testimine curl käsuga

Saad testida serveri endpointe otse curl käsuga. Selleks on vaja luua JSON-failid päringu kehadega. Repositooriumis peaksid olema näidisfailid (password.json, publickey.json, config.json).

Valmista ette JSON failid:

password.json:

```json
{
  "username": "testkasutaja",
  "password": "BASE64_ENCODED_PASSWORD",
  "connectionId": "test-connection-id-pass",
  "remoteAddress": "127.0.0.1"
}
```
Kodeeri parool: echo -n "kasutajaParool" | base64 -w 0

publickey.json:

```json
{
  "username": "testkasutaja",
  "publicKey": "ssh-rsa AAAAB3NzaC1yc2EAAA...",
  "connectionId": "test-connection-id-pubkey",
  "remoteAddress": "127.0.0.1"
}
```
Kasuta võtit authorized_keys formaadis.

config.json:

```json
{
  "username": "testkasutaja",
  "connectionId": "test-connection-id-config",
  "remoteAddress": "127.0.0.1"
}
```
Käivita curl käsud (eeldades, et server jookseb localhost:8888)
Testi parooliautentimist (kasutab password.json
```bash
curl -s -X POST -d @password.json -H 'Content-Type: application/json' http://localhost:8888/password
```
Testi avaliku võtme autentimist
```bash
curl -s -X POST -d @publickey.json -H 'Content-Type: application/json' http://localhost:8888/pubkey
```
Testi konfiguratsioonipäringut
```bash
curl -s -X POST -d @config.json -H 'Content-Type: application/json' http://localhost:8888/config
```
Analüüsi vastuseid (nt {"success": true} või konfiguratsiooni JSON).

### 🐳 Docker Image Ehitamine

Komplektis olev Dockerfile võimaldab ehitada serverist Docker image'i. Kasuta docker buildx mitmeplatvormilise image'i ehitamiseks (nt linux/amd64 ja linux/arm64):

Ehita ja lükka registrisse oma docker image (asenda oma kasutaja/repo nimega)
```bash
docker buildx build --builder=container --platform linux/arm64,linux/amd64 \
  -t markosoom/auth_configserver_ldap:latest \
  -t markosoom/auth_configserver_ldap:0.5 \
  . -f Dockerfile --push
```

Asenda :latest ja :0.5 sobivate siltidega.
--push lipp lükkab image'i pärast ehitamist registrisse.

### ☸️ Kubernetes Deployment

Kui kasutad ContainerSSH-d kuberneteses, saad selle webhook-serveri deploy'da eraldi Pod'ina ja Service'ina. Näidiskonfiguratsioon kubernetes.yaml on repositooriumis olemas.

Rakenda konfiguratsioon oma klastris:
```bash
kubectl apply -f kubernetes.yaml
```
See loob tavaliselt Deployment-i ja Service-i nimega auth-config-server. Veendu, et ContainerSSH konfiguratsioonis (vt ContainerSSH konfigureerimine) oleksid webhook URL-id õigesti seadistatud viitama sellele Service'ile (nt http://auth-config-server.default.svc.cluster.local:8888, kui see on default namespace'is).

### 💡 Täiendavad Märkused
LDAP Struktuur

Kood eeldab teatud LDAP struktuuri ja atribuutide nimesid:

Kasutaja leidmiseks kasutatakse LDAP_USER_DN_TEMPLATE malli (nt uid=kasutajanimi,ou=users,...).
Kasutaja otsimiseks kasutatakse LDAP_SEARCH_FILTER_TEMPLATE malli (nt (uid=kasutajanimi)).
Avaliku võtme hoidmiseks eeldatakse LDAP_SSH_PUBLIC_KEY_ATTR atribuuti (nt sshPublicKey). See võti peab LDAP-is olemas olema avaliku võtmega autentimiseks.
Kui anonüümne otsing pole lubatud, on vaja readonly õigustega LDAP_BIND_DN ja LDAP_BIND_PASSWORD kontot.
Kohanda neid keskkonnamuutujaid vastavalt oma LDAP skeemile.


Avaliku võtme lisamine /config sammus konteineri authorized_keys faili on toimiv, kuid mõnevõrra ebatavaline lahendus ContainerSSH jaoks. See muudab konteineri käivitamiskäsku (command või entrypoint), et lisada võti enne tegeliku shelli käivitamist. 

Kui soovid lubada ainult parooliga autentimist ja pead keelata avaliku võtmega autentimise, eemalda auth.publicKey sektsioon ContainerSSH konfiguratsioonifailist (containerssh.yaml).

```yaml
auth:
  password:
    method: webhook
    webhook:
      url: http://auth-config-server.default.svc.cluster.local:8888/password # Või muu sobiv URL
      timeout: 5s
  # publicKey: <--- See osa eemalda või kommenteeri välja
  #   method: webhook
  #   webhook:
  #     url: http://auth-config-server.default.svc.cluster.local:8888/pubkey
  #     timeout: 5s
```
### 🤝 Kaastöö
Kaastööd on teretulnud! Palun järgi üldisi häid tavasid:

Fork'i see repositoorium.
Loo uus haru (git checkout -b feature/uus-funktsioon).
Tee oma muudatused.
Commit'i muudatused (git commit -am 'Lisa uus funktsioon').
Push'i haru (git push origin feature/uus-funktsioon).
Ava pull request.
Vigadest teatamiseks või funktsioonisoovide esitamiseks loo uus Issue.

### 📜 Litsents
See projekt on litsentseeritud [MIT, Apache 2.0] litsentsi alusel.
