# Passive Biometric Authentication System

Система пасивної біометричної автентифікації для веб-додатків.

## Швидкий старт

```bash
# Клонування та запуск
cd passive-biometric-auth
docker-compose up --build
```

Система буде доступна за адресою: http://localhost

## Структура проєкту

```
passive-biometric-auth/
├── backend/              # FastAPI backend
│   ├── app/
│   │   ├── api/          # API endpoints
│   │   ├── core/         # Config, DB, Security
│   │   ├── models/       # SQLAlchemy models
│   │   ├── schemas/      # Pydantic schemas
│   │   └── services/     # Business logic
│   └── requirements.txt
├── frontend/             # Static frontend
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
├── docker/
│   └── init.sql          # DB initialization
└── docker-compose.yml
```

## API Endpoints

- `POST /api/auth/register` - Реєстрація
- `POST /api/auth/login` - Вхід
- `POST /api/auth/verify-mfa` - Верифікація MFA
- `POST /api/biometric/collect` - Збір біометрії
- `POST /api/biometric/analyze` - Аналіз поведінки
- `GET /api/dashboard/user` - Dashboard користувача

## Конфігурація

Налаштування в `.env`:
- `TRUST_SCORE_THRESHOLD=0.7` - Поріг trust score для MFA
- `SESSION_TIMEOUT_MINUTES=30` - Тайм-аут сесії

## Автор

Стельмах Дмитро, ТВ-52мп
