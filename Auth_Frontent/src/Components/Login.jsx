import { useForm } from "react-hook-form"; 
import { useContext, useState } from "react"; 
import { AuthContext } from "../Context/AuthContext"; 
import { useNavigate } from "react-router-dom"; 
import { TextField, Button, Container, Typography, Alert } from "@mui/material";  

const Login = () => {   
  const {     
    register,     
    handleSubmit,     
    formState: { errors },   
  } = useForm();   
  const { signIn } = useContext(AuthContext);   
  const navigate = useNavigate();
  const [error, setError] = useState(null);
    
  const onSubmit = async (data) => {     
    try {       
      console.log("Göndərilən data:", data);       
      await signIn(data);       
      navigate("/dashboard");     
    } catch (error) {       
      console.error("Login xətası:", error);
      setError("Giriş uğursuz oldu. Məlumatları yoxlayın.");
      console.log("Göndərilən məlumatlar:", data);     
    }   
  };    

  return (     
    <Container maxWidth="xs">       
      <Typography variant="h4" sx={{ mt: 4, mb: 2 }}>Login</Typography>       
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
      )}
      
      <form onSubmit={handleSubmit(onSubmit)}>         
        <TextField           
          label="Username"           
          fullWidth           
          margin="normal"           
          {...register("username", { required: "Username is required" })}           
          error={!!errors.username}           
          helperText={errors.username?.message}         
        />          
        
        <TextField           
          label="Password"           
          type="password"           
          fullWidth           
          margin="normal"           
          {...register("password", { required: "Password is required" })}           
          error={!!errors.password}           
          helperText={errors.password?.message}         
        />          
        
        <Button 
          type="submit" 
          variant="contained" 
          fullWidth 
          sx={{ mt: 2 }}
        >
          Login         
        </Button>       
      </form>     
    </Container>   
  ); 
};  

export default Login;