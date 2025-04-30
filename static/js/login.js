<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>

        document.addEventListener('DOMContentLoaded', function() {
            // Network visualization
            const canvas = document.getElementById('networkCanvas');
            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            
            // Particles for network visualization
            class Particle {
                constructor() {
                    this.x = Math.random() * canvas.width;
                    this.y = Math.random() * canvas.height;
                    this.size = Math.random() * 3 + 1;
                    this.speedX = Math.random() * 2 - 1;
                    this.speedY = Math.random() * 2 - 1;
                    this.color = this.getRandomColor();
                }
                
                getRandomColor() {
                    const colors = [
                        'rgba(65, 100, 74, 0.7)',  // Primary - #41644A
                        'rgba(233, 118, 43, 0.7)', // Secondary - #E9762B
                        'rgba(13, 71, 21, 0.7)',   // Accent - #0D4715
                        'rgba(255, 255, 255, 0.5)' // White
                    ];
                    return colors[Math.floor(Math.random() * colors.length)];
                }
                
                update() {
                    this.x += this.speedX;
                    this.y += this.speedY;
                    
                    if(this.x > canvas.width || this.x < 0) {
                        this.speedX = -this.speedX;
                    }
                    if(this.y > canvas.height || this.y < 0) {
                        this.speedY = -this.speedY;
                    }
                }
                
                draw() {
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
                    ctx.fillStyle = this.color;
                    ctx.fill();
                }
            }
            
            // Create particle array
            const particleArray = [];
            const numberOfParticles = 100;
            
            function createParticles() {
                for(let i = 0; i < numberOfParticles; i++) {
                    particleArray.push(new Particle());
                }
            }
            
            function connectParticles() {
                for(let a = 0; a < particleArray.length; a++) {
                    for(let b = a; b < particleArray.length; b++) {
                        const dx = particleArray[a].x - particleArray[b].x;
                        const dy = particleArray[a].y - particleArray[b].y;
                        const distance = Math.sqrt(dx * dx + dy * dy);
                        
                        if(distance < 150) {
                            ctx.beginPath();
                            ctx.strokeStyle = 'rgba(255, 255, 255, ' + (1 - distance/150) * 0.3 + ')';
                            ctx.lineWidth = 1;
                            ctx.moveTo(particleArray[a].x, particleArray[a].y);
                            ctx.lineTo(particleArray[b].x, particleArray[b].y);
                            ctx.stroke();
                        }
                    }
                }
            }
            
            function animate() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                
                for(let i = 0; i < particleArray.length; i++) {
                    particleArray[i].update();
                    particleArray[i].draw();
                }
                
                connectParticles();
                requestAnimationFrame(animate);
            }
            
            createParticles();
            animate();
            
            // Resize event
            window.addEventListener('resize', function() {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
                particleArray.length = 0;
                createParticles();
            });
            
            // Show activity log on hover near bottom left
            document.addEventListener('mousemove', function(e) {
                const activityLog = document.getElementById('activityLog');
                const threshold = 150;
                
                if (e.clientX < threshold && e.clientY > (window.innerHeight - threshold)) {
                    activityLog.style.display = 'block';
                } else {
                    activityLog.style.display = 'none';
                }
            });
            
            // Login form submission
            const loginForm = document.getElementById('loginForm');
            const notification = document.getElementById('notification');
            const notificationText = document.getElementById('notificationText');
            const dangerZone = document.getElementById('dangerZone');
            const threatStatus = document.getElementById('threatStatus');
            const logEntries = document.getElementById('logEntries');
            let loginAttempts = 0;
            
            loginForm.addEventListener('submit', function(e) {
                e.preventDefault();
                
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                loginAttempts++;
                
                // Add log entry
                const now = new Date();
                const timeString = now.getHours() + ':' + 
                                  (now.getMinutes() < 10 ? '0' : '') + now.getMinutes() + ':' +
                                  (now.getSeconds() < 10 ? '0' : '') + now.getSeconds();
                
                // Simulate login logic - just show notification that data would be sent to server
                showNotification('Login attempt recorded. Ready to connect to backend.', 'info');
                addLogEntry(`[${timeString}] Login attempt from user: ${username}`);
                
                // Show danger zone after 3 failed attempts
                if(loginAttempts >= 3) {
                    dangerZone.style.display = 'flex';
                    threatStatus.classList.remove('active');
                    threatStatus.classList.add('warning');
                    threatStatus.parentElement.innerHTML = threatStatus.outerHTML + ' Threat Level: Elevated';
                }
            });
            
            function showNotification(message, type) {
                notificationText.textContent = message;
                
                if(type === 'success') {
                    notification.style.background = 'rgba(65, 100, 74, 0.9)';
                } else if(type === 'info') {
                    notification.style.background = 'rgba(233, 118, 43, 0.9)';
                } else {
                    notification.style.background = 'rgba(220, 53, 69, 0.9)';
                }
                
                notification.classList.add('show');
                
                setTimeout(function() {
                    notification.classList.remove('show');
                }, 3000);
            }
            
            function addLogEntry(text) {
                const entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.textContent = text;
                
                logEntries.prepend(entry);
                
                // Keep only last 5 entries
                while(logEntries.children.length > 5) {
                    logEntries.removeChild(logEntries.lastChild);
                }
            }
            
            // Add some random log entries
            const logMessages = [
                'Packet inspection completed',
                'Firewall rule #2458 updated',
                'System scan scheduled for 03:00',
                'Configuration backup created',
                'API authentication token refreshed',
                'Database integrity check passed',
                'SSL certificate valid (expires in 45 days)',
                'Network traffic analysis completed'
            ];
            
            function addRandomLogEntry() {
                const now = new Date();
                const timeString = now.getHours() + ':' + 
                                  (now.getMinutes() < 10 ? '0' : '') + now.getMinutes() + ':' +
                                  (now.getSeconds() < 10 ? '0' : '') + now.getSeconds();
                
                const randomMessage = logMessages[Math.floor(Math.random() * logMessages.length)];
                addLogEntry(`[${timeString}] ${randomMessage}`);
                
                // Schedule next random log
                setTimeout(addRandomLogEntry, Math.random() * 8000 + 5000);
            }
            
            setTimeout(addRandomLogEntry, 3000);
        });
   