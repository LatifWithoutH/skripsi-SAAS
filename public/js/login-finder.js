// public/js/login-finder.js

document.addEventListener('DOMContentLoaded', () => {
  // 1. Inisialisasi ikon Lucide (jika belum di-init di tempat lain)
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }

  // 2. Ambil elemen DOM
  const form = document.getElementById('finderForm');
  if (!form) return; // Keluar jika bukan di halaman finder

  const submitBtn = document.getElementById('submitBtn');
  const btnText = document.getElementById('btnText');
  const btnIcon = document.getElementById('btnIcon');
  const btnSpinner = document.getElementById('btnSpinner');
  
  const modal = document.getElementById('resultModal');
  const modalSuccess = document.getElementById('modalSuccess');
  const modalError = document.getElementById('modalError');
  const modalInstitutionName = document.getElementById('modalInstitutionName');
  const modalErrorMessage = document.getElementById('modalErrorMessage');
  
  let targetUrl = '';

  // 3. Fungsi Menutup Modal (dibuat global agar bisa dipanggil onclick di HTML)
  window.closeModal = function() {
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
    if (form) form.reset();
    if (submitBtn) {
      submitBtn.disabled = false;
      btnText.textContent = 'Lanjutkan ke Login';
      btnIcon.classList.remove('hidden');
      btnSpinner.classList.add('hidden');
    }
  };

  // 4. Logic Submit Form dengan Fetch (AJAX)
  form.addEventListener('submit', async function(e) {
    e.preventDefault(); // Mencegah reload halaman standar

    // Aktifkan Loading State
    submitBtn.disabled = true;
    btnText.textContent = 'Mencari...';
    btnIcon.classList.add('hidden');
    btnSpinner.classList.remove('hidden');

    const formData = new FormData(form);

    try {
      const response = await fetch('/find-workspace', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-Requested-With': 'XMLHttpRequest' 
        },
        body: new URLSearchParams(formData)
      });

      const data = await response.json();

      if (response.ok && data.success) {
        targetUrl = data.url;
        modalInstitutionName.textContent = data.name || 'Institusi Anda';
        modalSuccess.classList.remove('hidden');
        modalError.classList.add('hidden');
      } else {
        modalErrorMessage.textContent = data.error || 'Institusi tidak ditemukan.';
        modalSuccess.classList.add('hidden');
        modalError.classList.remove('hidden');
      }

      // Tampilkan Modal
      if (modal) {
        modal.classList.remove('hidden');
        modal.classList.add('flex');
        if (typeof lucide !== 'undefined') lucide.createIcons();
      }

    } catch (error) {
      console.error('Fetch error:', error);
      alert('Terjadi kesalahan jaringan. Silakan coba lagi.');
      submitBtn.disabled = false;
      btnText.textContent = 'Lanjutkan ke Login';
      btnIcon.classList.remove('hidden');
      btnSpinner.classList.add('hidden');
    }
  });

  // 5. Event Listener untuk Tombol di dalam Modal
  const btnOpenSameTab = document.getElementById('btnOpenSameTab');
  const btnOpenNewTab = document.getElementById('btnOpenNewTab');

  if (btnOpenSameTab) {
    btnOpenSameTab.addEventListener('click', () => { window.location.href = targetUrl; });
  }
  if (btnOpenNewTab) {
    btnOpenNewTab.addEventListener('click', () => { 
      window.open(targetUrl, '_blank'); 
      window.closeModal(); 
    });
  }
});
