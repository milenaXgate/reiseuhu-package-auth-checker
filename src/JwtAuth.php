<?php namespace Vapost\ReiseuhuAuthChecker;

use \Firebase\JWT\JWT;
use \Carbon\Carbon;
use Closure;

class JwtAuth {
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
    	$token = $request->bearerToken();
    	
    	$key = env('JWT_SECRET');
    	
    	try {
    		
    		$decoded = JWT::decode($token, $key, array('HS256'));
    		$exp = Carbon::createFromTimestamp($decoded->exp);
    		$now = Carbon::now();
    		
    		if($now->gt($exp)) {
    			throw new \Exception('Token expired');
    		}
    		
    	} catch(\Exception $e)
    	{
    		return response('Token signature invalid: ' . $e->getMessage() , 401)
    		->header('Content-Type', 'application/json');
    	}
    	
    	return $next($request);
    }
}