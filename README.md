# Press Open Plugins

A collection of open-source WordPress plugins created and maintained by [@sameehj](https://github.com/sameehj) for custom automation, integration, and publishing workflows.

## 🔌 About This Repository

This repository serves as a home for simple, lightweight, and functional WordPress plugins built with clarity and open collaboration in mind. All plugins here are intended to be:

- 🔓 Open source and free to use
- 🛠️ Easy to understand and extend
- 💡 Built for real-world publishing, automation, and content workflows

## 📦 Included Plugins

### 1. `presshook`

A minimal custom webhook handler for WordPress.

**Description:**  
Allows you to create and manage custom webhook endpoints in your WordPress admin. Useful for integrations with external services like payment processors, CRMs, or automation tools.

**Tested with:**  
- ✅ [LemonSqueezy](https://www.lemonsqueezy.com/) (payment/received webhook events)
- ✅ [GreenInvoice](greeninvoice) (custom signature headers)

**Features:**
- Create webhook endpoints with ease
- Handle external POST requests securely
- Supports signature verification (customizable)
- Extendable for additional webhook topics or services

**Path:**  
`presshook/presshook.php`

**Status:**  
✅ Actively maintained

---

## 🔧 Installation

1. Clone the repository or download the specific plugin directory.
2. Upload the plugin folder (e.g., `presshook/`) to your WordPress site's `wp-content/plugins/` directory.
3. Activate the plugin from your WordPress admin dashboard.

---

## 🛠 Development

Feel free to fork, improve, or suggest new features. Contributions are welcome via pull requests or issues.

```bash
git clone https://github.com/sameehj/press-open-plugins.git
````

---

## 📜 License

All plugins in this repository are open-sourced under the [MIT License](LICENSE).

---

## 🤝 Contributing

If you'd like to contribute a plugin or improve an existing one:

1. Fork the repo
2. Add your plugin in a new directory
3. Include a `README.md` inside your plugin folder
4. Submit a pull request

---

## 🙌 Acknowledgements

Built with love by [Sameeh Jubran](https://github.com/sameehj) to support open publishing and automation tools for WordPress.