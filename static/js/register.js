<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>

        document.addEventListener('DOMContentLoaded', function() {
            const registerForm = document.getElementById('registerForm');

            registerForm.addEventListener('submit', function(e) {
                e.preventDefault();

                const username = document.getElementById('username').value;
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                const confirmPassword = document.getElementById('confirmPassword').value;

                if (password === confirmPassword) {
                    alert('Registration Successful!');
                } else {
                    alert('Passwords do not match!');
                }
            });
        });
