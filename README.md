# Katymio-dumper - Luau Script Dumper Bot

Discord bot que deobfusca y analiza scripts Lua/Luau obfuscados con seguridad mejorada.

## 🚀 Características

- **Deobfuscación Avanzada**: Detecta y deobfusca patrones comunes de ofuscación
- **Escaneo de Seguridad**: Detecta scripts maliciosos antes y después del dump
- **Multi-deployment**: Compatible con Railway y deployment local
- **Límites de Seguridad**: Timeouts, límites de tamaño, detección de ciclos
- **Sandbox Seguro**: Ejecución controlada de scripts Lua

## 📋 Requisitos

- Python 3.10+
- Lua 5.1+ o LuaJIT
- Discord Bot Token

## 🔧 Instalación Local

### Linux/macOS

```bash
# 1. Clonar el repositorio
git clone https://github.com/Francy2468/Katymio-dumper.git
cd Katymio-dumper

# 2. Ejecutar script de setup
chmod +x setup.sh
./setup.sh

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env y agregar tu DISCORD_TOKEN
```

### Windows

```powershell
# 1. Clonar el repositorio
git clone https://github.com/Francy2468/Katymio-dumper.git
cd Katymio-dumper

# 2. Instalar Lua (descargar de lua.org)

# 3. Instalar dependencias Python
pip install -r requirements.txt

# 4. Configurar variables de entorno
copy .env.example .env
# Editar .env y agregar tu DISCORD_TOKEN
```

## 🐳 Deployment con Docker

```bash
# Build
docker-compose build

# Run
docker-compose up -d

# Ver logs
docker-compose logs -f
```

## ☁️ Deployment en Railway

### Opción 1: Desde GitHub (Recomendado)

1. Haz fork de este repositorio
2. Ve a [Railway.app](https://railway.app)
3. Crea un nuevo proyecto
4. Conecta tu repositorio de GitHub
5. Agrega la variable de entorno:
   - `DISCORD_TOKEN`: Tu token de bot de Discord
6. Deploy automático ✨

### Opción 2: Railway CLI

```bash
# Instalar Railway CLI
npm install -g @railway/cli

# Login
railway login

# Inicializar proyecto
railway init

# Agregar variables de entorno
railway variables set DISCORD_TOKEN=tu_token_aqui

# Deploy
railway up
```

## 🎮 Uso

Una vez que el bot esté en línea:

```
Comando: .l [attachment | url]

Ejemplos:
1. .l (con archivo adjunto .lua, .luau o .txt)
2. .l https://example.com/script.lua
3. .l https://pastebin.com/raw/abc123
```

### Tipos de Archivo Aceptados

- `.lua` - Scripts Lua estándar
- `.luau` - Scripts Luau (Roblox)
- `.txt` - Archivos de texto con código Lua

### Límites

- **Tamaño máximo**: 8 MB (límite de Discord)
- **Timeout**: 30 segundos por script
- **Output máximo**: 8 MB

## 🔒 Características de Seguridad

El bot escanea automáticamente archivos en busca de:

- ✅ Descubrimiento de rutas del sistema (`debug.getinfo`, `/proc/self/`)
- ✅ Ejecución de comandos shell (`os.execute`, `io.popen`)
- ✅ Acceso a archivos sensibles (`/etc/passwd`, rutas absolutas)
- ✅ Exfiltración de variables de entorno
- ✅ Ofuscación pesada (heurísticas)

Los archivos peligrosos son **bloqueados automáticamente** y se genera una alerta.

## 📁 Estructura del Proyecto

```
Katymio-dumper/
├── bot.py              # Bot principal de Discord
├── scanner.py          # Escáner de seguridad
├── dumper.lua          # Script Lua deobfuscador
├── requirements.txt    # Dependencias Python
├── Dockerfile          # Configuración Docker
├── docker-compose.yml  # Orquestación Docker
├── Procfile            # Configuración Railway/Heroku
├── railway.toml        # Configuración Railway
├── setup.sh            # Script de instalación
├── .env.example        # Template de variables de entorno
└── tests/              # Tests unitarios
    ├── test_bot.py
    └── test_scanner.py
```

## 🧪 Testing

```bash
# Ejecutar todos los tests
python -m pytest tests/

# Con coverage
python -m pytest --cov=. tests/

# Test específico
python -m pytest tests/test_bot.py
```

## 🛠️ Configuración Avanzada

### Variables de Entorno

```bash
# Requerido
DISCORD_TOKEN=tu_token_de_discord

# Opcional
LOG_LEVEL=INFO          # DEBUG, INFO, WARNING, ERROR, CRITICAL
MAX_FILE_SIZE_MB=8      # Tamaño máximo de archivo en MB
```

### Configuración del Dumper (dumper.lua)

Edita las constantes en la parte superior de `dumper.lua`:

```lua
local CONFIG = {
    MAX_DEPTH = 16,                    -- Profundidad máxima de recursión
    MAX_TABLE_ITEMS = 200,             -- Items máximos por tabla
    MAX_OUTPUT_SIZE = 8 * 1024 * 1024, -- Límite de output (8MB)
    TIMEOUT_SECONDS = 8.0,             -- Timeout de ejecución
    TRACE_CALLS = true,                -- Habilitar tracing de funciones
}
```

## 🤝 Contribuir

Las contribuciones son bienvenidas! Por favor:

1. Fork el proyecto
2. Crea una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 📝 Changelog

### v2.0.0 (2026-03-09)

- ✨ Dumper Luau completamente reescrito
- 🔒 Sistema de seguridad mejorado (pre y post-dump)
- 🐳 Soporte Docker completo
- ☁️ Configuración optimizada para Railway
- 📚 Documentación expandida
- 🧪 Tests mejorados
- 🎨 Código refactorizado y más limpio

### v1.0.0

- 🎉 Release inicial

## 📜 Licencia

Este proyecto es de código abierto y está disponible bajo la licencia MIT.

## ⚠️ Disclaimer

Este bot está diseñado con fines educativos y de investigación de seguridad. No nos hacemos responsables del uso indebido de esta herramienta. Úsalo de manera responsable y ética.

## 🆘 Soporte

Si encuentras algún problema:

1. Revisa los [Issues existentes](https://github.com/Francy2468/Katymio-dumper/issues)
2. Crea un nuevo Issue con:
   - Descripción del problema
   - Pasos para reproducir
   - Logs relevantes
   - Tu entorno (OS, versión Python, etc.)

## 📞 Contacto

- **GitHub**: [@Francy2468](https://github.com/Francy2468)
- **Proyecto**: [Katymio-dumper](https://github.com/Francy2468/Katymio-dumper)

---

⭐ Si este proyecto te ayudó, considera darle una estrella en GitHub!