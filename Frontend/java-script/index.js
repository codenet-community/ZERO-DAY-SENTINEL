
// Custom cursor
document.addEventListener('DOMContentLoaded', function() {
    const cursor = document.querySelector('.cursor');
    
    document.addEventListener('mousemove', function(e) {
        cursor.style.left = e.clientX + 'px';
        cursor.style.top = e.clientY + 'px';
    });
    
    document.addEventListener('mousedown', function() {
        cursor.style.transform = 'translate(-50%, -50%) scale(0.7)';
    });
    
    document.addEventListener('mouseup', function() {
        cursor.style.transform = 'translate(-50%, -50%) scale(1)';
    });
    
    const links = document.querySelectorAll('a, button, .nav-item, .social-icon, .carousel-btn, .dot');
    
    links.forEach(link => {
        link.addEventListener('mouseenter', function() {
            cursor.style.transform = 'translate(-50%, -50%) scale(1.5)';
            cursor.style.backgroundColor = 'rgba(147, 51, 234, 0.7)';
        });
        
        link.addEventListener('mouseleave', function() {
            cursor.style.transform = 'translate(-50%, -50%) scale(1)';
            cursor.style.backgroundColor = 'rgba(147, 51, 234, 0.3)';
        });
    });
    
    // Mobile menu toggle
    const menuToggle = document.getElementById('menu-toggle');
    const navLinks = document.getElementById('nav-links');
    
    if (menuToggle && navLinks) {
        menuToggle.addEventListener('click', function() {
            menuToggle.classList.toggle('active');
            navLinks.classList.toggle('active');
        });
        
        // Close menu when clicking on a link
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', function() {
                menuToggle.classList.remove('active');
                navLinks.classList.remove('active');
            });
        });
    }
    
    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    });
    
    // Testimonial carousel
    const testimonialItems = document.querySelectorAll('.testimonial-item');
    const dotsContainer = document.getElementById('carousel-dots');
    const prevBtn = document.getElementById('prev-btn');
    const nextBtn = document.getElementById('next-btn');
    const dots = document.querySelectorAll('.dot');
    
    let currentIndex = 0;
    const autoSlideInterval = 6000;
    let autoSlideTimer;
    
    function showSlide(index) {
        testimonialItems.forEach(item => {
            item.classList.remove('active');
        });
        
        dots.forEach(dot => {
            dot.classList.remove('active');
        });
        
        testimonialItems[index].classList.add('active');
        dots[index].classList.add('active');
        currentIndex = index;
        
        resetAutoSlideTimer();
    }
    
    function nextSlide() {
        let nextIndex = currentIndex + 1;
        if (nextIndex >= testimonialItems.length) {
            nextIndex = 0;
        }
        showSlide(nextIndex);
    }
    
    function prevSlide() {
        let prevIndex = currentIndex - 1;
        if (prevIndex < 0) {
            prevIndex = testimonialItems.length - 1;
        }
        showSlide(prevIndex);
    }
    
    function resetAutoSlideTimer() {
        clearInterval(autoSlideTimer);
        autoSlideTimer = setInterval(nextSlide, autoSlideInterval);
    }
    
    if (prevBtn && nextBtn && dots.length > 0) {
        prevBtn.addEventListener('click', prevSlide);
        nextBtn.addEventListener('click', nextSlide);
        
        dots.forEach((dot, index) => {
            dot.addEventListener('click', function() {
                showSlide(index);
            });
        });
        
        // Start auto slide
        resetAutoSlideTimer();
    }
    
    // Feature cards animation on scroll
    const featureCards = document.querySelectorAll('.feature-card');
    
    function animateOnScroll() {
        featureCards.forEach((card, index) => {
            const cardPosition = card.getBoundingClientRect().top;
            const screenPosition = window.innerHeight / 1.2;
            
            if (cardPosition < screenPosition) {
                setTimeout(() => {
                    card.classList.add('animated');
                }, 200 * index);
            }
        });
    }
    
    window.addEventListener('scroll', animateOnScroll);
    
    // Trigger initial animations
    animateOnScroll();
    
    // Stats counter animation
    const statNumbers = document.querySelectorAll('.stat-number');
    let countersStarted = false;
    
    function startCounters() {
        if (countersStarted) return;
        
        const statsSection = document.querySelector('.stats');
        const statsSectionPosition = statsSection.getBoundingClientRect().top;
        const screenPosition = window.innerHeight / 1.2;
        
        if (statsSectionPosition < screenPosition) {
            countersStarted = true;
            
            statNumbers.forEach(stat => {
                const target = parseInt(stat.getAttribute('data-count'));
                let count = 0;
                const duration = 2000; // 2 seconds
                const increment = target / (duration / 16); // 60fps
                
                const updateCount = () => {
                    if (count < target) {
                        count += increment;
                        stat.textContent = Math.ceil(count);
                        requestAnimationFrame(updateCount);
                    } else {
                        stat.textContent = target;
                    }
                };
                
                updateCount();
            });
        }
    }
    
    window.addEventListener('scroll', startCounters);
    window.addEventListener('load', startCounters);
    
    // Contact form animation
    const contactForm = document.getElementById('contact-form');
    
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            // Add form submission logic here
            alert('Thank you for your message! We will get back to you soon.');
            contactForm.reset();
        });
    }
});
    