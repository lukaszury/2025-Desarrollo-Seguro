// src/services/fileService.ts
import fs from 'fs';
import path from 'path';
import { promisify } from 'util';
import db from '../db';

const unlink = promisify(fs.unlink);

// Implementar un directorio seguro para almacenar fotos de perfil
const PROFILE_PICTURES_DIR = path.resolve(process.env.UPLOAD_PATH || './uploads/profiles');

class FileService {
  static async saveProfilePicture(
    userId: string,
    file: any //Express.Multer.File
  ): Promise<string> {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user) throw new Error('User not found');

    if (user.picture_path) {
      try { await unlink(path.resolve(user.picture_path)); } catch { /*ignore*/ }
    }

    await db('users')
      .update({ picture_path: file.path })
      .where({ id: userId });

    return `${process.env.API_BASE_URL}/uploads/${path.basename(file.path)}`;
  }

  static async getProfilePicture(userId: string) {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user || !user.picture_path) throw new Error('No profile picture');
    
    // En vez de tomar el path como viene, validar que el archivo esté en el directorio permitido que definimos antes
    const fileName = path.basename(user.picture_path); // TOmar solamente el nombre del archivo
    const safePath = path.resolve(PROFILE_PICTURES_DIR, fileName); // Con esto se construye una ruta segura
    
    // Verificar que la ruta final está dentro del directorio permitido
    if (!safePath.startsWith(PROFILE_PICTURES_DIR)) {
      throw new Error('Invalid file path');
    }
    
    // Verificar que el archivo existe
    if (!fs.existsSync(safePath)) {
      throw new Error('Profile picture file not found');
    }

    const stream   = fs.createReadStream(safePath);
    const ext      = path.extname(safePath).toLowerCase();
    const contentType =
      ext === '.png'  ? 'image/png'  :
      ext === '.jpg'  ? 'image/jpeg' :
      ext === '.jpeg'? 'image/jpeg' : 
      'application/octet-stream';

    return { stream, contentType };
  }

  static async deleteProfilePicture(userId: string) {
    const user = await db('users')
      .select('picture_path')
      .where({ id: userId })
      .first();
    if (!user || !user.picture_path) throw new Error('No profile picture');

    // Igual que antes, validar que el archivo esté en el directorio permitido
    const fileName = path.basename(user.picture_path);
    const safePath = path.resolve(PROFILE_PICTURES_DIR, fileName);
    
    // Verificar que la ruta final está dentro del directorio permitido
    if (!safePath.startsWith(PROFILE_PICTURES_DIR)) {
      throw new Error('Invalid file path');
    }

    try { await unlink(safePath); } catch { /*ignore*/ } // Usar ruta segura

    await db('users')
      .update({ picture_path: null })
      .where({ id: userId });
  }
}

export default FileService;
