FROM python:3.11-slim


# Set the working directory in the container
WORKDIR /app


# Copy the dependencies file to the working directory
COPY requirements.txt .


# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt


# Copy the rest of your app's source code from your computer to the container
COPY . .


# Expose the port your app runs on
EXPOSE 8000


# Define the command to run your app
# We use Uvicorn here, the recommended server for FastAPI
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--access-log"]