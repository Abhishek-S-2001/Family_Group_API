from fastapi import Depends, HTTPException, Header
from supabase import Client
from app.utils.database import get_db

# Notice we changed Header(...) to Header(None)
def get_current_user_id(authorization: str = Header(None), db: Client = Depends(get_db)):
    """
    Dependency that extracts the JWT token from the header,
    verifies it with Supabase, and returns the secure user_id.
    """
    
    # 1. Catch missing headers completely and force a 401
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header format. Must be 'Bearer <token>'")
    
    # Extract the token string
    token = authorization.split(" ")[1]
    
    try:
        # Ask Supabase to verify the token and get the user data
        user_response = db.auth.get_user(token)
        
        if not user_response or not user_response.user:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
            
        # Return the verified UUID!
        return user_response.user.id
        
    except Exception as e:
        # Guarantee a 401 even if Supabase throws a 400 AuthApiError under the hood
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")