FROM python:latest

# Display python version
RUN python -m pip install --upgrade pip && \
    python --version

# Copy wheel files to /app
WORKDIR /app
COPY dist/*.whl .

# Install packages. This will ensure that all dependencies of wheels are installed
RUN pip install --find-links /app/*.whl autograph_config_sanitizer-*.whl

# Remove all wheels to save space
RUN rm -rf *.whl

# Change the user to a non-root user
USER 1234

# Run the API
CMD ["python", "-m", "autograph_config_sanitizer"]
