
// VIREON GROUP - FRONTEND JAVASCRIPT

// Mobile navigation
const menuButton = document.querySelector(".menu-toggle");
const nav = document.querySelector(".nav");

menuButton?.addEventListener("click", () => {
  const isOpen = nav?.classList.toggle("open") ?? false;
  menuButton.setAttribute("aria-expanded", String(isOpen));
});

// Close menu after clicking a navigation link
nav?.querySelectorAll("a").forEach(link => {
  link.addEventListener("click", () => {
    nav.classList.remove("open");
    menuButton?.setAttribute("aria-expanded", "false");
  });
});

// Automatic footer year
const yearElement = document.getElementById("year");

if (yearElement) {
  yearElement.textContent = new Date().getFullYear();
}

// Contact form submission
const form = document.getElementById("contact-form");

form?.addEventListener("submit", async event => {
  event.preventDefault();

  const status = form.querySelector(".form-status");
  const button = form.querySelector('button[type="submit"]');

  if (!button || !status) return;

  button.disabled = true;
  status.textContent = "Sending your enquiry…";

  try {
    const formData = Object.fromEntries(
      new FormData(form).entries()
    );

    const response = await fetch("/api/contact", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(formData)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(
        result.error || "Unable to send your enquiry."
      );
    }

    form.reset();

    status.textContent =
      result.message ||
      "Thank you. Your enquiry has been received.";

  } catch (error) {
    console.error("Contact form error:", error);

    status.textContent =
      error.message === "Failed to fetch"
        ? "Unable to connect to the enquiry service. Please try again later."
        : error.message || "Something went wrong. Please try again.";

  } finally {
    button.disabled = false;
  }
});
