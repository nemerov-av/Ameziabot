FROM python:3.10-slim

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем зависимости и устанавливаем их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копируем исходный код
COPY . .

# Создаем папку для базы данных, которую будем пробрасывать наружу
RUN mkdir -p /app/data

# Запуск скрипта
CMD ["python", "main.py"]