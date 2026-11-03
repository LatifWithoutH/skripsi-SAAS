# Menggunakan versi Node.js LTS yang stabil
FROM node:20-alpine

# Set environment default
ENV NODE_ENV=development

# Set direktori kerja di dalam container
WORKDIR /app

# Salin package.json dan install dependencies
COPY package*.json ./
RUN npm install

# Salin seluruh kode sumber
COPY . .

# Expose port 3000 (Port internal aplikasi)
EXPOSE 3000

# Gunakan user non-root untuk keamanan (best practice)
USER node

# Perintah untuk menjalankan aplikasi
CMD ["node", "app.js"]