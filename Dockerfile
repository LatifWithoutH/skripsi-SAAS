# Menggunakan versi Node.js LTS yang stabil
FROM node:18-alpine

# Set direktori kerja di dalam container
WORKDIR /app

# Salin package.json dan install dependencies
COPY package*.json ./
RUN npm install

# Salin seluruh kode sumber
COPY . .

# Expose port 3000 (Port internal aplikasi)
EXPOSE 3000

# Perintah untuk menjalankan aplikasi
CMD ["node", "app.js"]