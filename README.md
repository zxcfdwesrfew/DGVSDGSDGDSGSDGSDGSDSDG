# BIO Studio (Node.js + Express + JSON)

Полностью рабочий BIO‑сервис уровня cops.bio/guns.lol. Авторизация через cookie-сессии, пароли в bcrypt, все данные в `data/users/users.json`, загрузки в `public/uploads`.

## Быстрый старт
1. Установка зависимостей: `npm install`
2. Запуск сервера: `node server.js`
3. Открыть: `http://localhost:3000` (landing), `http://localhost:3000/register`, `http://localhost:3000/dashboard`

## API
- `POST /api/register` `{ username, password, plan? }`
- `POST /api/login` `{ username, password }`
- `POST /api/logout`
- `GET /api/me`
- `GET /api/profile/:username?increment=false` — выдаёт профиль, счётчик просмотров
- `POST /api/profile/save` — сохраняет профиль, ссылки, виджеты, музыку
- `POST /api/upload` — загрузка avatar/banner/background/audio/video в `/public/uploads`
- `GET /api/sparkle/:color?user=:username` — защищённая выдача sparkle GIF из `data/assets`

## Возможности
- Layouts Card/Left/Center, overlay эффекты, enter-анимации, sparkles (premium), кастомные шрифты, SEO, cursor/trail/cat, reveal screen, title animations, parallax 3D tilt.
- Виджеты: просмотры, аудио (до 3 треков, top/bottom/below card), локация. Поддержка mp4 для баннера/фона/аватара.
- Ссылки до 25 шт. (url/mail/phone, block/icon, иконки, tooltip), бейджи с тултипами, join date, счётчик просмотров.
- Дашборд: вкладки Home/Account/Customize/Links/Assets/Settings, range‑ползунки с live preview, сохранение с debounce, аналитика просмотров по диапазонам.
- Sparkles выдаются только через API по авторизации или если включены у пользователя (без прямого доступа к файлам).
