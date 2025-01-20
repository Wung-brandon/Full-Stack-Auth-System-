import { useState } from 'react';
import { FaEye, FaEyeSlash } from 'react-icons/fa';

const Login = () => {
  const [passwordVisible, setPasswordVisible] = useState(false);
  

  const togglePasswordVisibility = () => {
    setPasswordVisible((prev) => !prev);
  };

  
  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="">
          <div className="card shadow-sm">
            <div className="card-body">
              <h2 className="text-left mb-4">Login</h2>
              <form>
                <div className="mb-3">
                  <label htmlFor="email" className="form-label">Email Address:</label>
                  <input 
                    type="email" 
                    className="form-control" 
                    name="email" 
                    placeholder="Enter your email" 
                  />
                </div>
                
                <div className="mb-3 position-relative">
                  <label htmlFor="password" className="form-label text-start">Password:</label>
                  <div className="input-group">
                    <input 
                      type={passwordVisible ? 'text' : 'password'} 
                      className="form-control" 
                      id="password" 
                      name="password" 
                      placeholder="Enter your password" 
                    />
                    <span className="input-group-text" onClick={togglePasswordVisibility} style={{ cursor: 'pointer' }}>
                      {passwordVisible ? <FaEyeSlash /> : <FaEye />}
                    </span>
                  </div>
                </div>
                
                <div className="d-grid">
                  <button type="submit" className="btn btn-primary">Login</button>
                </div>
              </form>
              {/* <h3>Or</h3>
              <div className='d-grid'>
                <button className='btn btn-success'>Sign Up with Github</button>
              </div>
              <div className="mt-2 d-grid">
                <button className='btn btn-secondary'>Sign Up with Google</button>
              </div> */}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
