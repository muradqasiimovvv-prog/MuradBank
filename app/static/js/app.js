// Close alert messages
document.querySelectorAll('.close-alert').forEach(btn => {
    btn.addEventListener('click', function() {
        this.parentElement.style.display = 'none';
    });
});

// Auto-close alerts after 5 seconds
document.querySelectorAll('.alert').forEach(alert => {
    setTimeout(() => {
        alert.style.display = 'none';
    }, 5000);
});

// Simple form validation
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        // Basic client-side validation only
    });
});
