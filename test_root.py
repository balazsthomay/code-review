def delete_user(user_id):
    import os
    os.system(f"rm -rf /users/{user_id}")
