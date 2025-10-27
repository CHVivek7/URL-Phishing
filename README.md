# URL Phishing Detection  
## [Live Demo](https://url-phishing-qddg.onrender.com/)

This project provides a **machine learning-based phishing URL detection
system**. Phishing websites mimic legitimate ones to trick users into
revealing sensitive information such as credentials, personal data, or
financial details. This tool analyzes various features of URLs and
classifies them as **legitimate** or **phishing**.

## 🚀 Introduction

Phishing attacks are one of the most common cybersecurity threats. To
counter them, this project applies **machine learning techniques** to
analyze URLs and detect malicious intent. Features like **HTTPS usage**,
**anchor tag structure**, and **website traffic data** significantly
influence classification performance.

## ✨ Features

-   🔍 **Phishing URL Detection:** Detects malicious URLs using trained
    ML models.\
-   📊 **Feature Importance Analysis:** Identifies crucial factors such
    as HTTPS, Anchor URLs, and Website Traffic.\
-   🌐 **Web Interface (Flask App):** Users can input URLs via a web app
    and get instant results.\
-   📓 **Jupyter Notebook:** Includes data exploration, model building,
    and evaluation.

## 🛠️ Installation

### 1. Clone the Repository

``` bash
git clone https://github.com/CHVivek7/URL-Phishing.git
cd URL-Phishing
```

### 2. Install Dependencies

If `requirements.txt` is present:

``` bash
pip install -r requirements.txt
```

Or install commonly used libraries manually:

``` bash
pip install flask pandas numpy scikit-learn joblib
```

## ▶️ Usage

### Run the Flask Web App

``` bash
python app.py
```

Open the browser at: `http://127.0.0.1:5000/`

### Use Jupyter Notebook

``` bash
jupyter notebook
```

Open `Phishing_URL_Detection.ipynb` to explore model training and
analysis.

## 🧰 Technologies Used

-   **Python** -- Core programming language\
-   **Flask** -- Web framework for the app\
-   **Scikit-learn** -- ML algorithms for classification\
-   **Pandas & NumPy** -- Data manipulation and preprocessing\
-   **Joblib** -- Model saving and loading\
-   **Jupyter Notebook** -- Research and experimentation

## 🤝 Contributing

Contributions are welcome! To contribute:

1.  Fork the repo\
2.  Create a new branch (`feature/your-feature` or `bugfix/your-fix`)\
3.  Commit your changes\
4.  Push to your fork\
5.  Open a Pull Request

## 📜 License

This project is licensed under the [MIT
License](https://opensource.org/licenses/MIT).

## 📬 Contact

**CHVivek7** -- [GitHub](https://github.com/CHVivek7)\
📧 Email: vivekch1225@gmail.com
