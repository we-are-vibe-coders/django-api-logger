# 🔐 Django API Logger

A powerful Django package for **API logging, monitoring, and security**.  
This package helps developers track API requests/responses, detect vulnerabilities, monitor suspicious activities, and get proactive alerts before customers face downtime.

---

## 🚀 Features
- **API Logging**
  - Logs all API requests & responses with metadata.
  - Measures processing time for each request.
  - Masks sensitive fields (e.g., passwords, tokens).

- **Security & Vulnerability Monitoring**
  - Detects unauthorized login attempts & brute force attacks.
  - Monitors suspicious payloads (e.g., SQL injection patterns).
  - Tracks abnormal API usage & suspicious sessions.

- **File Upload Monitoring**
  - Restricts file types (whitelisted extensions).
  - Enforces file size limits.
  - Blocks suspicious filenames (e.g., `.php.jpg`).

- **Alerting System**
  - Threshold-based alerts (high latency, error spikes, suspicious traffic).
  - Notifications via Email, Slack, Webhooks, etc.
  - Priority levels: Critical, Warning, Info.

- **Dashboard & Reports**
  - Django Admin integration.
  - Logs, charts, and suspicious activity reports.
  - File upload activity monitoring.

---

## 📦 Installation

```bash
pip install django-api-logger
```
Add it to your `INSTALLED_APPS` in `settings.py`:

```python
INSTALLED_APPS = [
    ...
    'django_api_logger',
]
```

Add the middleware:

```python
MIDDLEWARE = [
    ...
    'django_api_logger.middleware.APILoggerMiddleware',
]
```

Run migrations:

```bash
python manage.py migrate 
```

## 🛠️ Configuration

You can configure the logger in your `settings.py`:

```python

# File monitoring
API_LOGGER_FILE_UPLOAD_MONITOR = {
    "max_size": 10 * 1024 * 1024,  # 10 MB
    "allowed_types": ["jpg", "png", "pdf"],
}

# Alerts
API_LOGGER_ALERTS = {
    "thresholds": {"response_time": 3, "error_rate": 10},
    "channels": ["email"],  # ["email", "slack", "webhook"]
}
```
## 📊 Admin Dashboard
Admin interface can be accessed at `/admin/api-logger/` to view logs and reports.

- View API logs (requests & responses).
- Track request time and bottlenecks.
- Monitor suspicious activity logs.
- File upload reports (blocked & successful).

## 🤝 Contributing

We welcome `contributions!` Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute.

## 📄 License
This project is licensed under the `MIT` License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Maintainers

- Anirudh MK (@anirudh-mk)

### Can you help us improve this package?

Do you wanna buy a `coffee` for the maintainers?  

[![Buy Me A Coffee](https://www.buymeacoffee.com/assets/img/custom_images/yellow_img.png)](https://buymeacoffee.com/wearevibect)
