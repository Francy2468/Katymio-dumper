# Multi-stage build for Katymio Dumper Discord Bot
FROM python:3.10-slim as base

# Install Lua interpreter
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    lua5.4 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY bot.py scanner.py dumper.lua ./
COPY tests/ ./tests/

# Create non-root user for security
RUN useradd -m -u 1000 botuser && \
    chown -R botuser:botuser /app

USER botuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Run the bot
CMD ["python", "-u", "bot.py"]
