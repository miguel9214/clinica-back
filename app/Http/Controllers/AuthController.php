<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Validation\ValidationException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;

class AuthController extends Controller
{


    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    public function register(Request $request)
    {

         try {
            $request->validate([
                'name'=>['required','string'],
                'email'=>['required','email','unique:users'],
                'password'=>['required','confirmed','min:8']
               ]);
         } catch (ValidationException $e) {
            response()->json(['error'=>$e->errors()]);
         }

          $user = new User;
          $user->name=$request->name;
          $user->email=$request->email;
          $user->password=bcrypt($request->password);

          $user->save();

          return response()->json(['message' => 'Successfully created user', 'data'=>$user]);

    }


    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);
    }


    public function user()
    {
        return response()->json(auth('api')->user());
    }

    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }


    public function refresh()
    {
        return $this->respondWithToken(auth('api')->refresh());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth('api')->factory()->getTTL() * 60
        ]);
    }
}
