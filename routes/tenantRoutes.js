const express = require('express');
const router = express.Router();
const mitraController = require('../controllers/mitraController');
const { ensureAuthenticated, checkPermission } = require('../middleware/tenantAuth');

// GET /mitra
router.get('/mitra', 
    ensureAuthenticated, 
    checkPermission('read:mitra'), 
    mitraController.getMitraPage
);

// POST /mitra/create
router.post('/mitra/create', 
    ensureAuthenticated, 
    checkPermission('write:mitra'), 
    mitraController.createMitra
);

// POST /mitra/update/:mitra_id
router.post('/mitra/update/:mitra_id', 
    ensureAuthenticated, 
    checkPermission('write:mitra'), 
    mitraController.updateMitra
);

// POST /mitra/delete/:mitra_id
router.post('/mitra/delete/:mitra_id', 
    ensureAuthenticated, 
    checkPermission('write:mitra'), 
    mitraController.deleteMitra
);

module.exports = router;