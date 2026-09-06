import type { NextFunction, Response } from 'express';
import jwt, { type JwtPayload } from 'jsonwebtoken';
import { type AuthenticatedRequest } from '../shared/http/authenticated-request.js';
import { touchSession } from '../services/session.service.js';

type AccessTokenPayload = JwtPayload & {
  id: number;
  sid: number;
};

function isAccessTokenPayload(payload: string | JwtPayload): payload is AccessTokenPayload {
  return typeof payload !== 'string' && Number.isInteger(payload.id) && Number.isInteger(payload.sid);
}

// Verifica el JWT de acceso, confirma que su sesión sigue activa y adjunta el usuario a la solicitud.
export async function authMiddleware(
  request: AuthenticatedRequest,
  response: Response,
  next: NextFunction,
) {
  const token = request.cookies?.accessToken as string | undefined;

  if (!token) {
    return response.status(401).json({
      code: 'NO_ACCESS_TOKEN',
      message: 'Acceso denegado',
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET!);

    if (!isAccessTokenPayload(decoded)) {
      return response.status(401).json({
        code: 'INVALID_SESSION_TOKEN',
        message: 'Token de sesión inválido',
      });
    }

    let session;

    try {
      session = await touchSession(decoded.sid, decoded.id);
    } catch (error) {
      console.error('Error actualizando la sesión:', error);

      return response.status(503).json({
        code: 'AUTH_SERVICE_UNAVAILABLE',
        message: 'El servicio de autenticación no está disponible',
      });
    }

    if (!session) {
      return response.status(401).json({
        code: 'SESSION_INACTIVE',
        message: 'Sesión inactiva',
      });
    }

    request.user = {
      id: decoded.id,
      sid: decoded.sid,
    };

    return next();
  } catch (error) {
    if (error instanceof jwt.TokenExpiredError) {
      return response.status(401).json({
        code: 'ACCESS_TOKEN_EXPIRED',
        message: 'Access token expired',
      });
    }

    return response.status(401).json({
      code: 'INVALID_ACCESS_TOKEN',
      message: 'Token inválido',
    });
  }
}
