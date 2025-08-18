const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");

// ==================================================================================================================================================

// --- Carregamento de Chaves ---
// Aponte para o diretório correto das chaves
const privateKey = fs.readFileSync(
  path.resolve(__dirname, "../keys/jwtRS512.key")
);
const publicKey = fs.readFileSync(
  path.resolve(__dirname, "../keys/jwtRS512.key.pub")
);

// ==================================================================================================================================================

// --- Funções de JWT ---

function checkToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, publicKey, (err, decoded) => {
      if (err) {
        return reject(err);
      }
      resolve(decoded);
    });
  });
}

// ==================================================================================================================================================

function signToken(jwtContent = {}) {
  return new Promise((resolve, reject) => {
    // Adiciona o timestamp 'iat' (issued at) em todas as assinaturas
    jwtContent.iat = Math.floor(Date.now() / 1000);
    jwt.sign(jwtContent, privateKey, { algorithm: "RS512" }, (err, token) => {
      if (err) {
        // Em caso de erro na assinatura, rejeitamos a promessa
        return reject(err);
      }
      resolve(token);
    });
  });
}

// ==================================================================================================================================================

function decodeToken(token) {
  return new Promise((resolve, reject) => {
    try {
      resolve(jwt.decode(token));
    } catch (err) {
      reject(err);
    }
  });
}

// ==================================================================================================================================================

// --- Carregamento de Dados ---

/**
 * Carrega e retorna os dados dos clientes do arquivo JSON.
 * @returns {Array} Array de objetos de cliente.
 */
function getClients() {
  const clientsData = fs.readFileSync(
    path.resolve(__dirname, "../db/client_data.json")
  );
  return JSON.parse(clientsData);
}

// ==================================================================================================================================================

/**
 * Encontra um cliente pelo seu client_id.
 * @param {string} clientId O ID do cliente a ser encontrado.
 * @returns {object|undefined} O objeto do cliente ou undefined se não for encontrado.
 */
function findClientById(clientId) {
  const clients = getClients();
  // No mundo real, isso seria uma query em um banco de dados (ex: SELECT * FROM clients WHERE client_id = ?)
  return clients.find((c) => c.client_id === clientId);
}

// ==================================================================================================================================================

module.exports = {
  checkToken,
  signToken,
  decodeToken,
  findClientById,
};

// ==================================================================================================================================================
