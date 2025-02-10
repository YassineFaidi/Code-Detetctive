# Use Python 3.12.3 base image
FROM python:3.12.3-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the Python script into the container
COPY code_detective.py /app/

# Install cppcheck
RUN apt-get update && apt-get install -y cppcheck

# Set the default command to run the script
ENTRYPOINT ["python", "code_detective.py"]