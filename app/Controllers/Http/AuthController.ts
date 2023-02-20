import type { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { schema, rules } from "@ioc:Adonis/Core/Validator";
import Admin from 'App/Models/Admin';
import User from 'App/Models/User';

export default class AuthController {
  public async userLogin({ request, response, auth }: HttpContextContract) {
    const loginSchema = schema.create({
      email: schema.string({ trim: true }, [rules.email()]),
      password: schema.string({ trim: true }),
    });
    const payload = await request.validate({ schema: loginSchema });

    try {
      const token = await auth
        .use("user")
        .attempt(payload.email, payload.password, {
          expiresIn: "1days",
        });

      return token.toJSON();
    } catch (error) {
      return response.json({ status: 400, message: "Invalid Credentials" });
    }
  }
  public async adminLogin({ request, response, auth }: HttpContextContract) {
    const loginSchema = schema.create({
      email: schema.string({ trim: true }, [rules.email()]),
      password: schema.string({ trim: true }),
    });
    const payload = await request.validate({ schema: loginSchema });

    try {
      const token = await auth
        .use("user")
        .attempt(payload.email, payload.password, {
          expiresIn: "1days",
        });

      return token.toJSON();
    } catch (error) {
      return response.json({ status: 400, message: "Invalid Credentials" });
    }
  }
  public async userRegister({ request, response, auth }: HttpContextContract) {
    const registerSchema = schema.create(
        {
            username: schema.string([
                rules.unique({ table: 'users', column: 'username' })
            ]),
            email: schema.string([
                rules.email(),
                rules.unique({ table: 'users', column: 'email' })
            ]),
            password: schema.string({ trim: true }),
        }
    );
    const payload = await request.validate({ schema: registerSchema });

    try {
    const user = await User.create(payload);
    const token = await auth
        .use("user")
        .attempt(payload.email, payload.password, {
          expiresIn: "1days",
    });

      return token.toJSON();
    } catch (error) {
      return response.json({ status: 400, message: "Invalid Credentials" });
    }
  }
  public async adminRegister({ request, response, auth }: HttpContextContract) {
    const registerSchema = schema.create(
        {
            username: schema.string([
                rules.unique({ table: 'admins', column: 'username' })
            ]),
            email: schema.string([
                rules.email(),
                rules.unique({ table: 'admins', column: 'email' })
            ]),
            password: schema.string({ trim: true }),
        }
    );
    const payload = await request.validate({ schema: registerSchema });

    try {
    const admin = await Admin.create(payload);
    const token = await auth
        .use("admin")
        .attempt(payload.email, payload.password, {
          expiresIn: "1days",
      });

      return token.toJSON()
    } catch (error) {
      return response.json({ status: 400, message: "Invalid Credentials" })
    }
  }
}
