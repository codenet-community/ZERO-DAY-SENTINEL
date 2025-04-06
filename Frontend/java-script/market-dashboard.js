// Initialize GSAP
gsap.registerPlugin(ScrollTrigger);

// Animate widgets on scroll
const widgets = document.querySelectorAll('.widget-container');
widgets.forEach((widget, index) => {
    gsap.from(widget, {
        scrollTrigger: {
            trigger: widget,
            start: "top bottom-=100",
            toggleActions: "play none none reverse"
        },
        duration: 1,
        y: 50,
        opacity: 0,
        scale: 0.95,
        ease: "power3.out",
        delay: index * 0.1
    });
});

// Animate CTA section
const ctaSection = document.querySelector('.cta-section');
gsap.from(ctaSection.children, {
    scrollTrigger: {
        trigger: ctaSection,
        start: "top center",
        toggleActions: "play none none reverse"
    },
    duration: 1,
    y: 30,
    opacity: 0,
    stagger: 0.2,
    ease: "power3.out"
});

// Add parallax effect to gradient overlay
window.addEventListener('mousemove', (e) => {
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    gsap.to('.gradient-overlay', {
        duration: 1,
        css: {
            background: `radial-gradient(circle at ${mouseX * 100}% ${mouseY * 100}%, rgba(147, 51, 234, 0.1), transparent 60%),
                        radial-gradient(circle at ${(1 - mouseX) * 100}% ${(1 - mouseY) * 100}%, rgba(147, 51, 234, 0.05), transparent 40%)`
        },
        ease: "power1.out"
    });
});

// Initialize GSAP
gsap.registerPlugin(ScrollTrigger);

// Animate widgets on scroll
const widgets = document.querySelectorAll('.widget-container');
widgets.forEach((widget, index) => {
    gsap.from(widget, {
        scrollTrigger: {
            trigger: widget,
            start: "top bottom-=100",
            toggleActions: "play none none reverse"
        },
        duration: 1,
        y: 50,
        opacity: 0,
        scale: 0.95,
        ease: "power3.out",
        delay: index * 0.1
    });
});

// Animate CTA section
const ctaSection = document.querySelector('.cta-section');
gsap.from(ctaSection.children, {
    scrollTrigger: {
        trigger: ctaSection,
        start: "top center",
        toggleActions: "play none none reverse"
    },
    duration: 1,
    y: 30,
    opacity: 0,
    stagger: 0.2,
    ease: "power3.out"
});

// Add parallax effect to gradient overlay
window.addEventListener('mousemove', (e) => {
    const mouseX = e.clientX / window.innerWidth;
    const mouseY = e.clientY / window.innerHeight;
    
    gsap.to('.gradient-overlay', {
        duration: 1,
        css: {
            background: `radial-gradient(circle at ${mouseX * 100}% ${mouseY * 100}%, rgba(147, 51, 234, 0.1), transparent 60%),
                        radial-gradient(circle at ${(1 - mouseX) * 100}% ${(1 - mouseY) * 100}%, rgba(147, 51, 234, 0.05), transparent 40%)`
        },
        ease: "power1.out"
    });
});

// Add hover effect to widgets
widgets.forEach(widget => {
    widget.addEventListener('mouseenter', () => {
        gsap.to(widget, {
            duration: 0.3,
            scale: 1.02,
            boxShadow: "0 8px 32px rgba(147, 51, 234, 0.15)",
            border: "1px solid rgba(147, 51, 234, 0.3)",
            ease: "power2.out"
        });

        // Animate the glow effect
        gsap.to(widget.querySelector('.glow-effect::before'), {
            duration: 0.5,
            opacity: 1,
            background: "linear-gradient(90deg, transparent, rgba(147, 51, 234, 0.5), transparent)",
            ease: "power2.out"
        });
    });

    widget.addEventListener('mouseleave', () => {
        gsap.to(widget, {
            duration: 0.3,
            scale: 1,
            boxShadow: "none",
            border: "1px solid rgba(147, 51, 234, 0.1)",
            ease: "power2.out"
        });

        // Reset the glow effect
        gsap.to(widget.querySelector('.glow-effect::before'), {
            duration: 0.5,
            opacity: 0.3,
            background: "linear-gradient(90deg, transparent, rgba(147, 51, 234, 0.3), transparent)",
            ease: "power2.out"
        });
    });
});

// Add hover effect to nav links
const navLinks = document.querySelectorAll('.nav-link');
navLinks.forEach(link => {
    link.addEventListener('mouseenter', () => {
        gsap.to(link, {
            duration: 0.3,
            color: '#9333ea',
            y: -2,
            ease: "power2.out"
        });
    });

    link.addEventListener('mouseleave', () => {
        gsap.to(link, {
            duration: 0.3,
            color: '#ffffff',
            y: 0,
            ease: "power2.out"
        });
    });
});

// Animate the AI dot
const aiDot = document.querySelector('.ai-dot');
gsap.to(aiDot, {
    duration: 2,
    scale: 1.5,
    opacity: 0.5,
    repeat: -1,
    yoyo: true,
    ease: "power1.inOut"
});

// Add smooth scroll behavior for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            gsap.to(window, {
                duration: 1,
                scrollTo: {
                    y: target,
                    offsetY: 80
                },
                ease: "power3.inOut"
            });
        }
    });
});

// Add animation to CTA button
const ctaButton = document.querySelector('.cta-button');
ctaButton.addEventListener('mouseenter', () => {
    gsap.to(ctaButton, {
        duration: 0.3,
        scale: 1.05,
        boxShadow: "0 8px 32px rgba(147, 51, 234, 0.3)",
        ease: "power2.out"
    });
});

ctaButton.addEventListener('mouseleave', () => {
    gsap.to(ctaButton, {
        duration: 0.3,
        scale: 1,
        boxShadow: "none",
        ease: "power2.out"
    });
});

// Initialize on page load
window.addEventListener('load', () => {
    // Fade in initial content
    gsap.to('body', {
        duration: 1,
        opacity: 1,
        ease: "power2.out"
    });
});