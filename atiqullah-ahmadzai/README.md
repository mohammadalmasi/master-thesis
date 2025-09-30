# Setup Instructions

## Prerequisites

Before starting, ensure you have the following prerequisites installed on your system:

- Python 3.11.9
- Sqlite3
- Git

## Step-by-Step Setup

### 1. Create a Project Directory

First, create a directory for your project and navigate into it:

```sh
mkdir safe_script
cd safe_script
```

### 2. Set Up a Virtual Environment

Create a virtual environment:

```sh
python3 -m venv env
```

### 3. Clone the Repository

Clone the project repository:

```sh
git clone https://git.fim.uni-passau.de/ahmadzai/sil2-project.git backend
```

### 4. Activating the environment

Active the virtual environment:

```sh
source env activate
env\Script\activate
cd backend
```

### 5. Install Dependencies

Install the required dependencies using the provided requirements.txt file:

`python3 install -r requirements.txt `

`or for mac `

`python3 install -r requirements_mac.txt `

`if you are still facing issues, try --force-reinstall`

### 6. Apply Database Migrations

Navigate to the api directory and apply the database migrations:

```sh
cd api


python manage.py migrate
```

### 7. Create a Superuser

Create a superuser account to access the Django admin interface:

```sh
python3 manage.py createsuperuser
```

Follow the prompts to set up the superuser account.

### 8. Start the Development Server

Finally, start the Django development server:

```sh
python3 manage.py runserver
```

The server should now be running, and you can access it at http://127.0.0.1:{assigned_port_number}/.

## Notes

Ensure you are using the exact versions of Keras, Gensim, and Numpy as specified in the requirements.txt file.

Always activate your virtual environment before running any commands by using `source env/bin/activate`

For any issues or further customization, refer to the project's documentation or contact the project maintainers.
