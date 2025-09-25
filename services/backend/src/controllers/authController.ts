import { Request, Response, NextFunction } from 'express';
import AuthService from '../services/authService';
import { User } from '../types/user';


const ping = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;
  try {
    res.json({"msg":"ok" });
  } catch (err) {
    next(err);
  }
};

const login = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;
  try {
    const user = await AuthService.authenticate(username, password);
    const token = await AuthService.generateJwt(user.id);
    res.json({ token, user });
  } catch (err) {
    next(err);
  }
};

const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email } = req.body;
  try {
    await AuthService.sendResetPasswordEmail(email);
    // 204: no content, but client knows email was sent
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { token, newPassword } = req.body;
  try {
    await AuthService.resetPassword(token, newPassword);
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const setPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { token, newPassword } = req.body;
  try {
    await AuthService.setPassword(token, newPassword);
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const createUser = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password, email, first_name, last_name } = req.body;
  try {
    const user: User = {
      username,
      password,
      email,
      first_name,
      last_name
    };
    const userDB = await AuthService.createUser(user);
    res.status(201).json(userDB);
  } catch (err) {
    next(err);
  }
};
//MITIGACION: EL problema con este metodo es que nunca verifica que el usuario
// a modificar sea el mismo que lo solicita. Podria ocurrir que un usuario modifique
//los datos de otro. La solucion es chequear que el usuario a modificar coincida
//con el que realiza la solicitud
const updateUser = async (req: Request, res: Response, next: NextFunction) => {
  //const userId = req.params.id;
  const targetUserId = req.params.id; //ID del usuario a modificar
  const currentUserId = (req as any).user?.id; //MITIGACION: ID del usuario autenticado
  const { username, password, email, first_name, last_name } = req.body;
  try {
    //MITIGACION: Verificar que coincidan los ID de usuario
    if (targetUserId !== currentUserId) {
      return res.status(403).json({
        error: 'Access denied: Solo puede modificar su propia cuenta.'
      })
    }
  const user: User = {
      username,
      password,
      email,
      first_name,
      last_name
    };
    const userDB = await AuthService.updateUser(user);
      res.status(201).json(userDB);
  } catch (err) {
    next(err);
  }
};

/*
export const getProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = await UserService.getById(req.user!.id);
    res.json(user);
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req: Request, res: Response, next: NextFunction) => {
  const { firstName, lastName } = req.body;
  try {
    const updated = await UserService.updateProfile(req.user!.id, { firstName, lastName });
    res.json(updated);
  } catch (err) {
    next(err);
  }
};

export const getPicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { stream, contentType } = await FileService.getProfilePicture(req.user!.id);
    res.setHeader('Content-Type', contentType);
    stream.pipe(res);
  } catch (err) {
    next(err);
  }
};

export const uploadPicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    const url = await FileService.saveProfilePicture(req.user!.id, req.file);
    res.json({ url });
  } catch (err) {
    next(err);
  }
};

export const deletePicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await FileService.deleteProfilePicture(req.user!.id);
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

*/



export default {
  ping,
  login,
  forgotPassword,
  resetPassword,
  setPassword,
  createUser,
  updateUser,
};