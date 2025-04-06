document.addEventListener('DOMContentLoaded', function() {
    // Simple animation for features list
    const features = document.querySelectorAll('.features li');
    
    features.forEach((feature, index) => {
        // Set initial state
        feature.style.opacity = '0';
        feature.style.transform = 'translateY(20px)';
        
        // Animate in with delay based on position
        setTimeout(() => {
            feature.style.transition = 'all 0.5s ease';
            feature.style.opacity = '1';
            feature.style.transform = 'translateY(0)';
        }, 400 + (index * 150));
    });
    
    // Simple button click effect
    const button = document.querySelector('.premium-button');
    button.addEventListener('click', function() {
        // Visual feedback
        this.style.transform = 'scale(0.98)';
        setTimeout(() => {
            this.style.transform = '';
            alert('Thank you for choosing Premium!');
        }, 200);
    });
});