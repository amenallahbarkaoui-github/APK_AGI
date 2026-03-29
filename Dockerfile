FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jre-headless \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install apktool
RUN wget -q https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    && wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar -O /usr/local/bin/apktool.jar

# Install JADX
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip -O /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -s /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip

# Install Android SDK build-tools (for apksigner)
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p ${ANDROID_HOME}/cmdline-tools \
    && wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/tools.zip \
    && unzip -q /tmp/tools.zip -d ${ANDROID_HOME}/cmdline-tools \
    && mv ${ANDROID_HOME}/cmdline-tools/cmdline-tools ${ANDROID_HOME}/cmdline-tools/latest \
    && rm /tmp/tools.zip \
    && yes | ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager --licenses > /dev/null 2>&1 \
    && ${ANDROID_HOME}/cmdline-tools/latest/bin/sdkmanager "build-tools;34.0.0" > /dev/null 2>&1

ENV PATH="${ANDROID_HOME}/build-tools/34.0.0:${PATH}"

# Set up workdir
WORKDIR /app

# Copy project
COPY . /app

# Install Python package
RUN pip install --no-cache-dir -e .

# Create workspace directory
RUN mkdir -p /workspace
ENV WORKSPACE_ROOT=/workspace

# Entry point
ENTRYPOINT ["apk-agent"]
CMD ["chat"]
