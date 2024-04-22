# CSGO Backend API

Ez a szoftver a [MIT licenc](LICENSE.txt) alatt áll.
A függőségekre vonatkozó szerzői jogi és licencadatok a [NOTICE.txt](NOTICE.txt)-ben találhatók.

## Az alkalmazás futtatása
1. Klónozd a Git-adattárat egy tetszőleges mappába:

*(Győződj meg róla, hogy a [Git](https://git-scm.com/downloads) telepítve van a parancs futtatása előtt!)*

`git clone https://github.com/ikt20230929/CSGOBackend`

2. Lépj be a mappába

`cd CSGOBackend\csgo`

3. Konfigurációs fájl szerkesztése

Az alkalmazás mappájában egy `appsettings.Development.json` nevű fájl található.

Nyisd meg, és váloztatsd meg az alábbi értékeket a környezetedhez képest:

- FrontUrl -> Változtatsd meg arra az elérési útra, ahonnan a Frontend-et el lehet érni. (pl. `https://example.com`)
- BackUrl -> Változtatsd meg arra az elérési útra, ahonnan a Backend-et el lehet érni. Állítsd be `http://localhost:5000`-re (nem `https://`!) ha a webszervered a fordított proxyzásra be van állítva!
- AccessTokenKey -> Változtatsd meg egy egyéni, véletlenszerű értékre.
- RefreshTokenKey -> Változtatsd meg egy egyéni, véletlenszerű értékre.
- ConnectionString -> Változtatsd meg az adatbázisod csatlakozási karakterláncára. Győződj meg róla, hogy a felhasználó rendelkezik a táblák létrehozásához és az adatok beszúrásához szükséges jogosultságokkal.
- AllowedHosts -> Változtatsd meg a BackUrl domain nevére (vagy fordított proxy esetén a kifordított domain névre (pl. `example.com`)

(Tipp: Ha csak helyileg teszteled az alkalmazást, akkor a ConnectionString-en kívűl valószínűleg nem kell semmi mást megváltoztatnod.)

4. Futtasd az alkalmazást

*(Győződj meg róla, hogy a [.NET SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0) telepítve van a parancs futtatása előtt!)*

Ha csak helyileg tesztelsz, futtasd a `dotnet run` parancsot, különben, kövesd az alábbi lépéseket a produkciós futtatáshoz:

```bash
# Másold át a fejlesztési konfigurációs fájlt a produkciós helyére.
copy appsettings.Development.json appsettings.json
(Linux-on: cp appsettings.Development.json appsettings.json)

# Az alkalmazás build-elése.
dotnet build -c Release

# Lépj be a mappába ami a build-elt állományokat tartalmazza.
cd bin\Release\net8.0

# Futtasd a szerver állományt.
csgo
```

## Tesztelés
Az egység teszteket a `dotnet test` paranccsal lehet futtatni.
