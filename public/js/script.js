// public/js/script.js

// ==========================================
// 1. INISIALISASI SAAT DOM LOADED
// ==========================================
document.addEventListener('DOMContentLoaded', function() {
    // Inisialisasi Lucide Icons
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
    
    // Auto-detect judul halaman (untuk halaman dashboard dkk)
    updatePageTitle();
    
    // Setup smooth scrolling untuk anchor links
    setupSmoothScrolling();
    
    // Setup navbar scroll effect
    setupNavbarScroll();
    
    // Setup animation on scroll
    setupScrollAnimations();
});

// ==========================================
// 2. FUNGSI UPDATE JUDUL HALAMAN
// ==========================================
function updatePageTitle() {
    const path = window.location.pathname;
    const titleMap = {
        '/dashboard': 'Dashboard',
        '/kerjasama': 'Dokumen Kerjasama',
        '/mitra': 'Data Mitra',
        '/users': 'Kelola Tim',
        '/platform/dashboard': 'Platform Overview',
        '/portal-mitra/dashboard': 'Portal Mitra'
    };
    
    const titleElement = document.getElementById('dynamic-page-title');
    if (titleElement && titleMap[path]) {
        titleElement.textContent = titleMap[path];
    }
}

// ==========================================
// 3. SMOOTH SCROLLING UNTUK ANCHOR LINKS
// ==========================================
function setupSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            const href = this.getAttribute('href');
            if (href !== '#') {
                e.preventDefault();
                const target = document.querySelector(href);
                if (target) {
                    const offsetTop = target.offsetTop - 80; // Adjust for fixed navbar
                    window.scrollTo({
                        top: offsetTop,
                        behavior: 'smooth'
                    });
                }
            }
        });
    });
}

// ==========================================
// 4. NAVBAR SCROLL EFFECT
// ==========================================
function setupNavbarScroll() {
    const navbar = document.querySelector('nav');
    if (!navbar) return;
    
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            navbar.classList.add('shadow-md');
            navbar.classList.add('bg-white/95');
        } else {
            navbar.classList.remove('shadow-md');
            navbar.classList.remove('bg-white/95');
        }
    });
}

// ==========================================
// 5. SCROLL ANIMATIONS
// ==========================================
function setupScrollAnimations() {
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);
    
    // Observe elements with animation classes
    document.querySelectorAll('.animate-fade-in-up').forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.8s ease-out, transform 0.8s ease-out';
        observer.observe(el);
    });
}

// ==========================================
// 6. FUNGSI-FUNGSI MODAL (GLOBAL)
// ==========================================

// Toggle modal umum
window.toggleModal = function(modalId) {
    const modal = document.getElementById(modalId || 'inviteModal') || 
                  document.getElementById('kerjasamaModal') || 
                  document.getElementById('addMitraModal');
    if (modal) {
        modal.classList.toggle('hidden');
        modal.classList.toggle('flex');
    }
};

// Buka modal invite
window.openInviteModal = function() {
    const modal = document.getElementById('inviteModal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }
};

// Tutup modal invite
window.closeInviteModal = function() {
    const modal = document.getElementById('inviteModal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
};

// Buka modal kerjasama
window.openKerjasamaModal = function() {
    const modal = document.getElementById('kerjasamaModal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }
};

// Tutup modal kerjasama
window.closeKerjasamaModal = function() {
    const modal = document.getElementById('kerjasamaModal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
};

// Buka modal tambah mitra
window.openAddModal = function() {
    const modal = document.getElementById('addMitraModal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }
};

// Tutup modal tambah mitra
window.closeAddModal = function() {
    const modal = document.getElementById('addMitraModal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
};

// Buka modal edit mitra
window.openEditModal = function(mitra) {
    // Pastikan data mitra ada
    if (!mitra) {
        console.error('Data mitra tidak ditemukan');
        return;
    }
    
    // Isi form dengan data mitra
    const editMitraId = document.getElementById('edit_mitra_id');
    const editMitraName = document.getElementById('edit_mitra_name');
    const editContactName = document.getElementById('edit_contact_name');
    const editContactEmail = document.getElementById('edit_contact_email');
    const editContactPhone = document.getElementById('edit_contact_phone');
    const editNotes = document.getElementById('edit_notes');
    
    if (editMitraId) editMitraId.value = mitra.id;
    if (editMitraName) editMitraName.textContent = mitra.name;
    if (editContactName) editContactName.value = mitra.contact_name || '';
    if (editContactEmail) editContactEmail.value = mitra.contact_email || '';
    if (editContactPhone) editContactPhone.value = mitra.contact_phone || '';
    if (editNotes) editNotes.value = mitra.notes || '';
    
    // Set action form
    const editForm = document.getElementById('editMitraForm');
    if (editForm) {
        editForm.action = `/mitra/update/${mitra.id}`;
    }
    
    // Tampilkan modal
    const modal = document.getElementById('editMitraModal');
    if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
    }
};

// Tutup modal edit mitra
window.closeEditModal = function() {
    const modal = document.getElementById('editMitraModal');
    if (modal) {
        modal.classList.add('hidden');
        modal.classList.remove('flex');
    }
};

// ==========================================
// 7. TUTUP MODAL KLIK DI LUAR (BACKDROP)
// ==========================================
window.onclick = function(event) {
    const modalIds = [
        'addMitraModal', 
        'editMitraModal', 
        'inviteModal', 
        'kerjasamaModal',
        'uploadModal'
    ];
    
    modalIds.forEach(id => {
        const modal = document.getElementById(id);
        if (modal && event.target === modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
        }
    });
};

// ==========================================
// 8. FUNGSI UTILITY LAINNYA
// ==========================================

// Toggle password visibility
window.togglePassword = function(inputId, button) {
    const input = document.getElementById(inputId);
    if (!input) return;
    
    const iconOpen = button.querySelector('.icon-eye-open');
    const iconClosed = button.querySelector('.icon-eye-closed');
    
    if (input.type === 'password') {
        input.type = 'text';
        if (iconOpen) iconOpen.classList.add('hidden');
        if (iconClosed) iconClosed.classList.remove('hidden');
    } else {
        input.type = 'password';
        if (iconOpen) iconOpen.classList.remove('hidden');
        if (iconClosed) iconClosed.classList.add('hidden');
    }
};

// Validasi password match
window.checkPasswordMatch = function(passwordId, confirmId, errorId) {
    const password = document.getElementById(passwordId);
    const confirm = document.getElementById(confirmId);
    const error = document.getElementById(errorId);
    
    if (!password || !confirm || !error) return;
    
    if (confirm.value.length > 0) {
        if (password.value !== confirm.value) {
            error.classList.remove('hidden');
            confirm.classList.add('border-red-300', 'bg-red-50');
            confirm.classList.remove('border-slate-300', 'bg-slate-50');
        } else {
            error.classList.add('hidden');
            confirm.classList.remove('border-red-300', 'bg-red-50');
            confirm.classList.add('border-slate-300', 'bg-slate-50');
        }
    }
};

// Format angka dengan separator
window.formatNumber = function(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ".");
};

// ==========================================
// 9. HANDLE FORM SUBMISSION
// ==========================================

// Tambahkan loading state pada form
document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        const submitBtn = this.querySelector('button[type="submit"]');
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <svg class="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span class="ml-2">Memproses...</span>
            `;
            
            // Restore button setelah request selesai (untuk form tanpa reload)
            setTimeout(() => {
                submitBtn.disabled = false;
                submitBtn.innerHTML = originalText;
            }, 5000); // Timeout 5 detik sebagai fallback
        }
    });
});

// ==========================================
// 10. CONSOLE LOG (DEBUG MODE)
// ==========================================
console.log('%c SIMITRADUDIKA ', 'background: #4f46e5; color: white; font-size: 16px; font-weight: bold; padding: 4px 8px; border-radius: 4px;');
console.log('%c Script loaded successfully ', 'color: #10b981;');