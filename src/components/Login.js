import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
const Login = (props)=>  {
    const [credentials,setCredentials] = useState({email:"",password:""})
    let navigate = useNavigate();
    const handelSubmit = async (e) =>{
        e.preventDefault();
        const response = await fetch("http://localhost:5000/api/auth/login", {
            method: 'POST', 
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({email: credentials.email, password: credentials.password }) 
          });

          const json = await response.json()
          console.log(json)
         if (json.success) {
          localStorage.setItem('token',json.authtoken);
           props.showAlert("Loggedin Successfully","success")
          navigate("/", { replace: true });

         } else {
          props.showAlert("Invalid Detail","danger")

         }
          
         
    }
    
    const onChange= (e) =>{
        setCredentials({...credentials, [e.target.name] : e.target.value})
   }
  return (
    <div className='mt-3' >
      <h2>Login to continue to iNotebook</h2>
     <form onSubmit={handelSubmit}>
        <div  className="mb-3">
            <label htmlFor="email"  className="form-label">Email address</label>
            <input type="email"  className="form-control" value={credentials.email} id="email" onChange={onChange} name='email' aria-describedby="emailHelp"/>
            <div id="emailHelp"  className="form-text">We'll never share your email with anyone else.</div>
        </div>
        <div  className="mb-3">
            <label htmlFor="password"   className="form-label">Password</label>
            <input type="password" value={credentials.password} className="form-control" onChange={onChange} id="password" name='password'/>
        </div>
        
        <button type="submit" onClick={()=> handelSubmit}  className="btn btn-primary">Submit</button>
        </form></div>
  )
}

export default Login
